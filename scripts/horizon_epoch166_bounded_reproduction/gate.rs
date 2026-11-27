//! Hold a bounded replay until its invocation passes the native guard and capacity checks.
use std::{
    env, fs, io,
    os::unix::{fs::MetadataExt, process::CommandExt},
    path::Path,
    process::Command,
    thread,
    time::{Duration, Instant},
};

#[cfg(not(any(epoch170_suffix, epoch170_continuation, epoch140_suffix)))]
mod route {
    pub(super) const EPOCH: u64 = 166;
    pub(super) const UNIT: &str =
        "horizon-qualify-166-write-version-reproduction-20261124-v1.service";
    pub(super) const ALIAS: &str = "/run/horizon-166-write-version-v1";
    pub(super) const RUN: &str = "/home/sol/.jetstreamer-private/epoch166-independent-cold-20261120-v1/bounded-write-version-20261124-v1";
    pub(super) const SNAPSHOT: &str =
        "snapshot-71998051-6GepGUiRjT1G4UpKJKDbCahrzyTeZLPqgZzw7g9td7jm.tar.zst";
    pub(super) const TERMINAL_SLOT: u64 = 72_004_310;
}
#[cfg(epoch170_suffix)]
mod route {
    pub(super) const EPOCH: u64 = 170;
    pub(super) const UNIT: &str = "horizon-qualify-170-checkpoint-suffix-20261127-v1.service";
    pub(super) const ALIAS: &str = "/run/horizon-170-checkpoint-suffix-v1";
    pub(super) const RUN: &str = "/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1/replacement-local3retry7-20261110-v1/replacement-local3retry10-20261121-v1/metered-hourly-20261124-v1/suffix-73706460-73879004-v1";
    pub(super) const SNAPSHOT: &str =
        "snapshot-73706460-3SF9c2ZeGqa8bL3mbVzeNeGNPCBgFBZCe2yj5r9pFUX7.tar.zst";
    #[cfg(not(epoch170_bridge))]
    pub(super) const TERMINAL_SLOT: u64 = 73_879_004;
    #[cfg(epoch170_bridge)]
    pub(super) const TERMINAL_SLOT: u64 = 73_726_716;
}
#[cfg(epoch140_suffix)]
mod route {
    pub(super) const EPOCH: u64 = 140;
    pub(super) const UNIT: &str = "horizon-epoch140-suffix-recording.service";
    pub(super) const ALIAS: &str = "/run/horizon140-suffix-gate";
    #[cfg(not(epoch140_suffix_retry))]
    pub(super) const RUN: &str =
        "/home/sol/.jetstreamer-private/epoch140-suffix-recording-20261127-v1";
    #[cfg(epoch140_suffix_retry)]
    pub(super) const RUN: &str =
        "/home/sol/.jetstreamer-private/epoch140-suffix-recording-20261127-retry1";
    pub(super) const TERMINAL_SLOT: u64 = 60_911_999;
}

#[cfg(epoch170_continuation)]
mod route {
    pub(super) const EPOCH: u64 = 170;
    pub(super) const UNIT: &str = "horizon-qualify-170-from-73726716-20261127-v1.service";
    pub(super) const ALIAS: &str = "/run/horizon-170-from-73726716-v1";
    pub(super) const SNAPSHOT: &str =
        "snapshot-73726716-FWdNzr1DnDLqiWmKfNtUbuBqmSz5gqJ3XE55d98LCw3M.tar.zst";
    #[cfg(epoch170_continuation_short)]
    pub(super) const RUN: &str = "/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1/from-73726716-to-73746882-v1";
    #[cfg(epoch170_continuation_short)]
    pub(super) const TERMINAL_SLOT: u64 = 73_746_882;
    #[cfg(not(epoch170_continuation_short))]
    pub(super) const RUN: &str = "/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1/from-73726716-to-73879004-v1";
    #[cfg(not(epoch170_continuation_short))]
    pub(super) const TERMINAL_SLOT: u64 = 73_879_004;
}
use route::*;
#[cfg(not(any(epoch170_suffix, epoch170_continuation)))]
const RELEASE_TIMEOUT: Duration = Duration::from_secs(180);
#[cfg(any(epoch170_suffix, epoch170_continuation))]
const RELEASE_TIMEOUT: Duration = Duration::from_secs(600);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);

#[cfg(all(epoch170_bridge, not(epoch170_suffix)))]
compile_error!("the short epoch 170 bridge must use the epoch 170 suffix gate");

#[cfg(all(epoch170_continuation_short, not(epoch170_continuation)))]
compile_error!("the short epoch 170 continuation requires its own gate");

#[cfg(not(epoch140_suffix))]
fn replay_args() -> Vec<String> {
    #[cfg(not(epoch170_bridge))]
    let (hashes, output, scratch) = (
        "canonical-hashes.txt",
        format!("epoch-{EPOCH}.diagnostic.jet"),
        "scratch",
    );
    #[cfg(epoch170_bridge)]
    let (hashes, output, scratch) = (
        "bridge-hashes.txt",
        format!("epoch-{EPOCH}.bridge-{TERMINAL_SLOT}.jet"),
        "scratch/bridge-73726716",
    );
    vec![
        EPOCH.to_string(),
        format!("{RUN}/ledger"),
        "--verify".into(),
        format!("--snapshot-archive={ALIAS}/{SNAPSHOT}"),
        format!("--epoch-hashes={ALIAS}/{hashes}"),
        format!("--horizon-output={RUN}/ledger/{output}"),
        format!("--replay-scratch={RUN}/{scratch}"),
        format!("--qualification-end-slot={TERMINAL_SLOT}"),
    ]
}

#[cfg(epoch140_suffix)]
fn recording_command() -> io::Result<(String, Vec<String>)> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let [digest] = args.as_slice() else {
        return Err(io::Error::other(
            "expected the sealed epoch 140 plan digest",
        ));
    };
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || !digest.bytes().any(|b| b != b'0')
    {
        return Err(io::Error::other("invalid epoch 140 plan digest"));
    }
    Ok((
        "/run/horizon140-suffix-node/jetstreamer-node".into(),
        vec![
            EPOCH.to_string(),
            RUN.into(),
            "--verify".into(),
            "--epoch140-suffix-plan=/run/horizon140-suffix-plan/plan.json".into(),
            format!("--epoch140-suffix-plan-sha256={digest}"),
        ],
    ))
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
        return Err(io::Error::other(format!(
            "invalid epoch {EPOCH} release file"
        )));
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
    #[cfg(epoch140_suffix)]
    let (executable, args) = recording_command()?;
    #[cfg(not(epoch140_suffix))]
    let (executable, args) = (format!("{ALIAS}/jetstreamer-node"), replay_args());
    #[cfg(not(epoch140_suffix))]
    if env::args_os().len() != 1 {
        return Err(io::Error::other(format!(
            "unexpected epoch {EPOCH} gate arguments"
        )));
    }
    let invocation = env::var("INVOCATION_ID").map_err(io::Error::other)?;
    let process = fs::metadata("/proc/self")?;
    if !invocation_id_is_valid(&invocation)
        || fs::read_to_string("/proc/self/cgroup")?.trim() != format!("0::/system.slice/{UNIT}")
        || (process.uid(), process.gid()) != (1001, 1003)
    {
        return Err(io::Error::other(format!(
            "unexpected epoch {EPOCH} gate identity"
        )));
    }
    let release = Path::new(ALIAS).join("barrier/allow");
    let started = Instant::now();
    let mut next_heartbeat = started + HEARTBEAT_INTERVAL;
    eprintln!(
        "epoch {EPOCH}: invocation {invocation} waiting at most {} seconds for guard and capacity release",
        RELEASE_TIMEOUT.as_secs()
    );
    while started.elapsed() < RELEASE_TIMEOUT {
        if is_released(&release, &invocation)? {
            eprintln!(
                "epoch {EPOCH}: invocation {invocation} released after {} seconds through slot {TERMINAL_SLOT}",
                started.elapsed().as_secs()
            );
            return Err(Command::new(executable).args(args).exec());
        }
        if Instant::now() >= next_heartbeat {
            eprintln!(
                "epoch {EPOCH}: invocation {invocation} still waiting for guard and capacity release, {} seconds remaining",
                RELEASE_TIMEOUT.saturating_sub(started.elapsed()).as_secs()
            );
            next_heartbeat += HEARTBEAT_INTERVAL;
        }
        thread::sleep(Duration::from_millis(200));
    }
    Err(io::Error::other(format!(
        "epoch {EPOCH} guard and capacity release expired"
    )))
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
    #[cfg(not(epoch140_suffix))]
    fn replay_uses_the_pinned_snapshot_and_private_bounded_output() {
        let args = replay_args();
        assert_eq!(args[0], EPOCH.to_string());
        assert_eq!(args[2], "--verify");
        assert_eq!(args[3], format!("--snapshot-archive={ALIAS}/{SNAPSHOT}"));
        #[cfg(not(epoch170_bridge))]
        assert_eq!(
            args[5],
            format!("--horizon-output={RUN}/ledger/epoch-{EPOCH}.diagnostic.jet")
        );
        #[cfg(epoch170_bridge)]
        {
            assert_eq!(args[4], format!("--epoch-hashes={ALIAS}/bridge-hashes.txt"));
            assert_eq!(
                args[5],
                format!("--horizon-output={RUN}/ledger/epoch-170.bridge-73726716.jet")
            );
            assert_eq!(
                args[6],
                format!("--replay-scratch={RUN}/scratch/bridge-73726716")
            );
            assert_eq!(
                (EPOCH, args[7].as_str()),
                (170, "--qualification-end-slot=73726716")
            );
        }
        #[cfg(not(any(epoch170_suffix, epoch170_continuation)))]
        assert_eq!(
            (EPOCH, args[7].as_str()),
            (166, "--qualification-end-slot=72004310")
        );
        #[cfg(all(epoch170_suffix, not(epoch170_bridge)))]
        assert_eq!(
            (EPOCH, args[7].as_str()),
            (170, "--qualification-end-slot=73879004")
        );
        #[cfg(epoch170_continuation)]
        {
            assert_eq!(EPOCH, 170);
            assert!(SNAPSHOT.starts_with("snapshot-73726716-"));
            assert_eq!(
                args[4],
                "--epoch-hashes=/run/horizon-170-from-73726716-v1/canonical-hashes.txt"
            );
            assert_eq!(args[6], format!("--replay-scratch={RUN}/scratch"));
            #[cfg(epoch170_continuation_short)]
            let (directory, end) = (
                "from-73726716-to-73746882-v1",
                "--qualification-end-slot=73746882",
            );
            #[cfg(not(epoch170_continuation_short))]
            let (directory, end) = (
                "from-73726716-to-73879004-v1",
                "--qualification-end-slot=73879004",
            );
            assert_eq!(Path::new(RUN).file_name().unwrap(), directory);
            assert_eq!(args[7], end);
        }
    }
}
