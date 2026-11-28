//! Hold a bounded replay until its invocation passes the native guard and capacity checks.
use std::{
    env, fs, io,
    os::unix::{fs::MetadataExt, process::CommandExt},
    path::Path,
    process::Command,
    thread,
    time::{Duration, Instant},
};

#[cfg(not(any(
    epoch170_suffix,
    epoch170_continuation,
    epoch140_suffix,
    epoch141_first_hourly,
    epoch141_third_hourly,
    epoch143_first_hourly,
    epoch162_second_hourly
)))]
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
#[cfg(any(all(any(epoch162_second_retry,epoch162_second_reserved), not(epoch162_second_hourly)), all(epoch162_second_retry,epoch162_second_reserved)))]
compile_error!("the 162 second-interval retry requires its bounded hourly route");
#[cfg(epoch162_second_hourly)]
mod route {
    pub(super) const EPOCH: u64 = 162;
    #[cfg(epoch162_second_reserved)]
    pub(super) const UNIT: &str = "horizon-qualify-162-second-replay-20261128-v3.service";
    #[cfg(epoch162_second_reserved)]
    pub(super) const ALIAS: &str = "/run/horizon-162-second-replay-v3";
    #[cfg(epoch162_second_reserved)]
    pub(super) const RUN: &str = "/home/sol/.jetstreamer-private/epoch162-second-replay-20261128-v3";
    #[cfg(not(any(epoch162_second_retry,epoch162_second_reserved)))]
    pub(super) const UNIT: &str = "horizon-qualify-162-second-replay-20261128-v1.service";
    #[cfg(epoch162_second_retry)]
    pub(super) const UNIT: &str = "horizon-qualify-162-second-replay-20261128-v2.service";
    #[cfg(not(any(epoch162_second_retry,epoch162_second_reserved)))]
    pub(super) const ALIAS: &str = "/run/horizon-162-second-replay-v1";
    #[cfg(epoch162_second_retry)]
    pub(super) const ALIAS: &str = "/run/horizon-162-second-replay-v2";
    #[cfg(not(any(epoch162_second_retry,epoch162_second_reserved)))]
    pub(super) const RUN: &str =
        "/home/sol/.jetstreamer-private/epoch162-second-replay-20261128-v1";
    #[cfg(epoch162_second_retry)]
    pub(super) const RUN: &str =
        "/home/sol/.jetstreamer-private/epoch162-second-replay-20261128-v2";
    pub(super) const SNAPSHOT: &str =
        "snapshot-69991076-H5hYSmFbbrjDMXyakVgeaDseLNC4t6NEYgsuJ8SYnE8F.tar.zst";
    pub(super) const TERMINAL_SLOT: u64 = 69_998_119;
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
    #[cfg(not(any(epoch140_suffix_retry, epoch140_suffix_retry2)))]
    pub(super) const RUN: &str =
        "/home/sol/.jetstreamer-private/epoch140-suffix-recording-20261127-v1";
    #[cfg(epoch140_suffix_retry)]
    pub(super) const RUN: &str =
        "/home/sol/.jetstreamer-private/epoch140-suffix-recording-20261127-retry1";
    #[cfg(epoch140_suffix_retry2)]
    pub(super) const RUN: &str =
        "/home/sol/.jetstreamer-private/epoch140-suffix-recording-20261127-retry2";
    pub(super) const TERMINAL_SLOT: u64 = 60_911_999;
}

#[cfg(epoch143_first_hourly)]
mod route {
    pub(super) const EPOCH: u64 = 143;
    pub(super) const UNIT: &str = "horizon-qualify-143-first-hourly-20261127-v1.service";
    pub(super) const ALIAS: &str = "/run/horizon143-first-hourly";
    pub(super) const RUN: &str = "/home/sol/.jetstreamer-private/epoch143-first-hourly-20261127-v1";
    pub(super) const SNAPSHOT: &str =
        "bootstrap/snapshot-61775538-65YRW5KRaq6JezqoEc9rUqnmgfp7TjVw3koFbnMtbuun.tar.zst";
    pub(super) const TERMINAL_SLOT: u64 = 61_787_631;
    pub(super) const NODE: &str = "/usr/local/lib/jetstreamer/deploy-epochs144-147-upgradeable-loader-20261016-v1/jetstreamer-node";
}

#[cfg(epoch141_first_hourly)]
mod route {
    pub(super) const EPOCH: u64 = 141;
    pub(super) const UNIT: &str = "horizon-qualify-141-first-hourly-20261127-v1.service";
    pub(super) const ALIAS: &str = "/run/horizon141-first-hourly";
    pub(super) const RUN: &str = "/home/sol/.jetstreamer-private/epoch141-first-hourly-20261127-v1";
    pub(super) const SNAPSHOT: &str =
        "bootstrap/snapshot-60911751-GyFbDnPnUWrFStHKfwWC98xJpmBQKjLyJ9sMf2m6MrWR.tar.zst";
    pub(super) const TERMINAL_SLOT: u64 = 60_921_282;
}

#[cfg(epoch141_third_hourly)]
mod route {
    pub(super) const EPOCH: u64 = 141;
    pub(super) const UNIT: &str = "horizon-qualify-141-third-hourly-20261127-v1.service";
    pub(super) const ALIAS: &str = "/run/horizon141-third-hourly";
    pub(super) const RUN: &str = "/home/sol/.jetstreamer-private/epoch141-third-hourly-20261127-v1";
    pub(super) const SNAPSHOT: &str =
        "bootstrap/snapshot-60928493-7jmzVuomxUeE3WeR1XStbdiH1EDVR61Kz44km6J2jwv2.tar.zst";
    pub(super) const TERMINAL_SLOT: u64 = 60_935_310;
}

#[cfg(all(
    epoch170_continuation,
    not(any(epoch170_from_73746882, epoch170_from_73760367, epoch170_from_73766969))
))]
mod route {
    pub(super) const EPOCH: u64 = 170;
    pub(super) const UNIT: &str = "horizon-qualify-170-from-73726716-20261127-v1.service";
    pub(super) const ALIAS: &str = "/run/horizon-170-from-73726716-v1";
    pub(super) const SNAPSHOT: &str =
        "snapshot-73726716-FWdNzr1DnDLqiWmKfNtUbuBqmSz5gqJ3XE55d98LCw3M.tar.zst";
    #[cfg(epoch170_continuation_short)]
    pub(super) const RUN: &str = "/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1/replacement-local3retry7-20261110-v1/replacement-local3retry10-20261121-v1/metered-hourly-20261124-v1/from-73726716-to-73746882-v1";
    #[cfg(epoch170_continuation_short)]
    pub(super) const TERMINAL_SLOT: u64 = 73_746_882;
    #[cfg(not(epoch170_continuation_short))]
    pub(super) const RUN: &str = "/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1/replacement-local3retry7-20261110-v1/replacement-local3retry10-20261121-v1/metered-hourly-20261124-v1/from-73726716-to-73879004-v1";
    #[cfg(not(epoch170_continuation_short))]
    pub(super) const TERMINAL_SLOT: u64 = 73_879_004;
}

#[cfg(all(epoch170_continuation, epoch170_from_73746882))]
mod route {
    pub(super) const EPOCH: u64 = 170;
    pub(super) const UNIT: &str = "horizon-qualify-170-from-73746882-20261127-v1.service";
    pub(super) const ALIAS: &str = "/run/horizon-170-from-73746882-v1";
    pub(super) const SNAPSHOT: &str =
        "snapshot-73746882-UjWmG6TowgFrbT6Ntd1vcH9m4E6LXX9AsaVG8727mW6.tar.zst";
    pub(super) const RUN: &str = "/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1/replacement-local3retry7-20261110-v1/replacement-local3retry10-20261121-v1/metered-hourly-20261124-v1/from-73746882-to-73766969-v1";
    pub(super) const TERMINAL_SLOT: u64 = 73_766_969;
}
#[cfg(all(epoch170_continuation, epoch170_from_73760367))]
mod route {
    pub(super) const EPOCH: u64 = 170;
    #[cfg(not(epoch170_gap_ram_retry))]
    pub(super) const UNIT: &str = "horizon-qualify-170-from-73760367-20261128-v1.service";
    #[cfg(all(epoch170_gap_ram_retry, not(any(epoch170_gap_ram_second, epoch170_gap_ram_third))))]
    pub(super) const UNIT: &str = "horizon-qualify-170-from-73760367-ram-20261128-v1.service";
    #[cfg(all(epoch170_gap_ram_retry, epoch170_gap_ram_second))]
    pub(super) const UNIT: &str = "horizon-qualify-170-from-73760367-ram-20261128-v2.service";
    #[cfg(all(epoch170_gap_ram_retry, epoch170_gap_ram_third))]
    pub(super) const UNIT: &str = "horizon-qualify-170-from-73760367-ram-20261128-v3.service";
    pub(super) const ALIAS: &str = "/run/horizon-170-from-73760367-v1";
    pub(super) const SNAPSHOT: &str =
        "snapshot-73760367-7gcF7iqN9FvU2JrCkdqX7DmeV1X1AvZaGYoJjrLkCrsF.tar.zst";
    #[cfg(not(epoch170_gap_ram_retry))]
    pub(super) const RUN: &str = "/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1/replacement-local3retry7-20261110-v1/replacement-local3retry10-20261121-v1/metered-hourly-20261124-v1/from-73760367-to-73766969-v1";
    #[cfg(all(epoch170_gap_ram_retry, not(any(epoch170_gap_ram_second, epoch170_gap_ram_third))))]
    pub(super) const RUN: &str = "/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1/replacement-local3retry7-20261110-v1/replacement-local3retry10-20261121-v1/metered-hourly-20261124-v1/from-73760367-to-73766969-ram-v1";
    #[cfg(all(epoch170_gap_ram_retry, epoch170_gap_ram_second))]
    pub(super) const RUN: &str = "/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1/replacement-local3retry7-20261110-v1/replacement-local3retry10-20261121-v1/metered-hourly-20261124-v1/from-73760367-to-73766969-ram-v2";
    #[cfg(all(epoch170_gap_ram_retry, epoch170_gap_ram_third))]
    pub(super) const RUN: &str = "/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1/replacement-local3retry7-20261110-v1/replacement-local3retry10-20261121-v1/metered-hourly-20261124-v1/from-73760367-to-73766969-ram-v3";
    pub(super) const TERMINAL_SLOT: u64 = 73_766_969;
}
#[cfg(all(epoch170_continuation, epoch170_from_73766969))]
mod route {
    pub(super) const EPOCH: u64 = 170;
    #[cfg(not(epoch170_after_checkpoint_gap))]
    pub(super) const UNIT: &str = "horizon-qualify-170-from-73766969-20261127-v1.service";
    #[cfg(epoch170_after_checkpoint_gap)]
    pub(super) const UNIT: &str = "horizon-qualify-170-from-73766969-gap-20261128-v1.service";
    pub(super) const ALIAS: &str = "/run/horizon-170-from-73766969-v1";
    pub(super) const SNAPSHOT: &str =
        "snapshot-73766969-9mYMWeKx1ZWjsBcGLUhmDGbdkY2GMCmdFnE6UxfAeQjW.tar.zst";
    pub(super) const RUN: &str = "/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1/replacement-local3retry7-20261110-v1/replacement-local3retry10-20261121-v1/metered-hourly-20261124-v1/from-73766969-to-73787145-v1";
    pub(super) const TERMINAL_SLOT: u64 = 73_787_145;
}
#[cfg(all(
    any(epoch170_from_73746882, epoch170_from_73760367, epoch170_from_73766969),
    any(
        not(epoch170_continuation),
        epoch170_continuation_short,
        all(
            epoch170_from_73746882,
            any(epoch170_from_73760367, epoch170_from_73766969)
        ),
        all(epoch170_from_73760367, epoch170_from_73766969)
    )
))]
compile_error!("each hourly epoch 170 checkpoint requires its dedicated continuation profile");
use route::*;
#[cfg(not(any(epoch170_suffix, epoch170_continuation, epoch162_second_hourly)))]
const RELEASE_TIMEOUT: Duration = Duration::from_secs(180);
#[cfg(any(epoch170_suffix, epoch170_continuation, epoch162_second_hourly))]
const RELEASE_TIMEOUT: Duration = Duration::from_secs(600);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);

#[cfg(all(epoch170_bridge, not(epoch170_suffix)))]
compile_error!("the short epoch 170 bridge must use the epoch 170 suffix gate");

#[cfg(all(epoch170_continuation_short, not(epoch170_continuation)))]
compile_error!("the short epoch 170 continuation requires its own gate");

#[cfg(not(epoch140_suffix))]
fn replay_args() -> Vec<String> {
    #[cfg(not(any(
        epoch170_bridge,
        epoch141_first_hourly,
        epoch141_third_hourly,
        epoch143_first_hourly
    )))]
    let (hashes, output, scratch) = (
        "canonical-hashes.txt",
        format!("ledger/epoch-{EPOCH}.diagnostic.jet"),
        "scratch",
    );
    #[cfg(epoch143_first_hourly)]
    let (hashes, output, scratch) = (
        "canonical-hashes.txt",
        "epoch-143-first-hourly.jet",
        "scratch",
    );
    #[cfg(epoch141_first_hourly)]
    let (hashes, output, scratch) = ("epoch-hashes.txt", "epoch-141-first-hourly.jet", "scratch");
    #[cfg(epoch141_third_hourly)]
    let (hashes, output, scratch) = ("epoch-hashes.txt", "epoch-141-third-hourly.jet", "scratch");
    #[cfg(epoch170_bridge)]
    let (hashes, output, scratch) = (
        "bridge-hashes.txt",
        format!("ledger/epoch-{EPOCH}.bridge-{TERMINAL_SLOT}.jet"),
        "scratch/bridge-73726716",
    );
    vec![
        EPOCH.to_string(),
        format!("{RUN}/ledger"),
        "--verify".into(),
        format!("--snapshot-archive={ALIAS}/{SNAPSHOT}"),
        format!("--epoch-hashes={ALIAS}/{hashes}"),
        format!("--horizon-output={RUN}/{output}"),
        format!("--replay-scratch={RUN}/{scratch}"),
        format!("--qualification-end-slot={TERMINAL_SLOT}"),
        #[cfg(any(epoch141_first_hourly, epoch141_third_hourly))]
        format!("--epoch141-original-index={ALIAS}/original/index.json"),
        #[cfg(any(epoch141_first_hourly, epoch141_third_hourly))]
        "--epoch141-original-index-sha256=fe38bd4ce018996349c10029720dd7f738340fb0ad30ce6b8577b9651bf87df3".into(),
        #[cfg(any(epoch141_first_hourly, epoch141_third_hourly))]
        format!("--epoch141-original-data={ALIAS}/original/original-entries.data"),
        #[cfg(any(epoch141_first_hourly, epoch141_third_hourly))]
        "--epoch141-original-data-sha256=5605dd1ba08b7e790227b0efc388a74a02cdf665220d2455c3ed39f803feada0".into(),
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

#[cfg(epoch143_first_hourly)]
fn check_bootstrap_binding(args: &[String]) -> io::Result<()> {
    let path = args
        .iter()
        .find_map(|argument| argument.strip_prefix("--snapshot-archive="))
        .ok_or_else(|| io::Error::other("missing epoch 143 snapshot argument"))?;
    let mut snapshot = fs::File::open(path)
        .map_err(|error| io::Error::new(error.kind(), format!("{path}: {error}")))?;
    let metadata = snapshot.metadata()?;
    let mut header = [0; 4];
    io::Read::read_exact(&mut snapshot, &mut header)?;
    if !metadata.is_file() || metadata.len() != 3_714_834_246 || header != [0x28, 0xb5, 0x2f, 0xfd]
    {
        return Err(io::Error::other(format!(
            "different epoch 143 snapshot at {path}"
        )));
    }
    eprintln!(
        "epoch 143 bootstrap binding {path} device={} inode={} bytes={}",
        metadata.dev(),
        metadata.ino(),
        metadata.len()
    );
    Ok(())
}

fn main() -> io::Result<()> {
    #[cfg(epoch140_suffix)]
    let (executable, args) = recording_command()?;
    #[cfg(not(any(epoch140_suffix, epoch143_first_hourly)))]
    let (executable, args) = (format!("{ALIAS}/jetstreamer-node"), replay_args());
    #[cfg(epoch143_first_hourly)]
    let (executable, args) = (NODE, replay_args());
    #[cfg(epoch143_first_hourly)]
    if env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--check-bootstrap-binding"))
        && env::args_os().len() == 2
    {
        return check_bootstrap_binding(&args);
    }
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
    #[cfg(epoch143_first_hourly)]
    check_bootstrap_binding(&args)?;
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
        #[cfg(epoch162_second_hourly)]
        {
            assert_eq!(args[0], "162");
            assert_eq!(
                args[4],
                format!("--epoch-hashes={ALIAS}/canonical-hashes.txt")
            );
            assert_eq!(args[7], "--qualification-end-slot=69998119");
            assert!(args[3].contains("snapshot-69991076-"));
        }
        #[cfg(not(any(
            epoch170_bridge,
            epoch141_first_hourly,
            epoch141_third_hourly,
            epoch143_first_hourly
        )))]
        assert_eq!(
            args[5],
            format!("--horizon-output={RUN}/ledger/epoch-{EPOCH}.diagnostic.jet")
        );
        #[cfg(epoch143_first_hourly)]
        {
            assert_eq!(
                args[3],
                "--snapshot-archive=/run/horizon143-first-hourly/bootstrap/snapshot-61775538-65YRW5KRaq6JezqoEc9rUqnmgfp7TjVw3koFbnMtbuun.tar.zst"
            );
            assert_eq!(
                args[4],
                format!("--epoch-hashes={ALIAS}/canonical-hashes.txt")
            );
            assert_eq!(
                args[5],
                format!("--horizon-output={RUN}/epoch-143-first-hourly.jet")
            );
            assert_eq!(args[6], format!("--replay-scratch={RUN}/scratch"));
            assert_eq!(
                (EPOCH, args[7].as_str()),
                (143, "--qualification-end-slot=61787631")
            );
        }
        #[cfg(epoch141_first_hourly)]
        assert_eq!(
            args,
            [
                "141",
                "/home/sol/.jetstreamer-private/epoch141-first-hourly-20261127-v1/ledger",
                "--verify",
                "--snapshot-archive=/run/horizon141-first-hourly/bootstrap/snapshot-60911751-GyFbDnPnUWrFStHKfwWC98xJpmBQKjLyJ9sMf2m6MrWR.tar.zst",
                "--epoch-hashes=/run/horizon141-first-hourly/epoch-hashes.txt",
                "--horizon-output=/home/sol/.jetstreamer-private/epoch141-first-hourly-20261127-v1/epoch-141-first-hourly.jet",
                "--replay-scratch=/home/sol/.jetstreamer-private/epoch141-first-hourly-20261127-v1/scratch",
                "--qualification-end-slot=60921282",
                "--epoch141-original-index=/run/horizon141-first-hourly/original/index.json",
                "--epoch141-original-index-sha256=fe38bd4ce018996349c10029720dd7f738340fb0ad30ce6b8577b9651bf87df3",
                "--epoch141-original-data=/run/horizon141-first-hourly/original/original-entries.data",
                "--epoch141-original-data-sha256=5605dd1ba08b7e790227b0efc388a74a02cdf665220d2455c3ed39f803feada0",
            ]
        );
        #[cfg(epoch141_third_hourly)]
        assert_eq!(
            args,
            [
                "141",
                "/home/sol/.jetstreamer-private/epoch141-third-hourly-20261127-v1/ledger",
                "--verify",
                "--snapshot-archive=/run/horizon141-third-hourly/bootstrap/snapshot-60928493-7jmzVuomxUeE3WeR1XStbdiH1EDVR61Kz44km6J2jwv2.tar.zst",
                "--epoch-hashes=/run/horizon141-third-hourly/epoch-hashes.txt",
                "--horizon-output=/home/sol/.jetstreamer-private/epoch141-third-hourly-20261127-v1/epoch-141-third-hourly.jet",
                "--replay-scratch=/home/sol/.jetstreamer-private/epoch141-third-hourly-20261127-v1/scratch",
                "--qualification-end-slot=60935310",
                "--epoch141-original-index=/run/horizon141-third-hourly/original/index.json",
                "--epoch141-original-index-sha256=fe38bd4ce018996349c10029720dd7f738340fb0ad30ce6b8577b9651bf87df3",
                "--epoch141-original-data=/run/horizon141-third-hourly/original/original-entries.data",
                "--epoch141-original-data-sha256=5605dd1ba08b7e790227b0efc388a74a02cdf665220d2455c3ed39f803feada0",
            ]
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
        #[cfg(not(any(
            epoch170_suffix,
            epoch170_continuation,
            epoch141_first_hourly,
            epoch141_third_hourly,
            epoch143_first_hourly,
            epoch162_second_hourly
        )))]
        assert_eq!(
            (EPOCH, args[7].as_str()),
            (166, "--qualification-end-slot=72004310")
        );
        #[cfg(all(epoch170_suffix, not(epoch170_bridge)))]
        assert_eq!(
            (EPOCH, args[7].as_str()),
            (170, "--qualification-end-slot=73879004")
        );
        #[cfg(epoch170_from_73746882)]
        {
            assert_eq!(EPOCH, 170);
            assert!(args[3].starts_with(
                "--snapshot-archive=/run/horizon-170-from-73746882-v1/snapshot-73746882-"
            ));
            assert_eq!(
                args[4],
                "--epoch-hashes=/run/horizon-170-from-73746882-v1/canonical-hashes.txt"
            );
            assert!(
                args[5].ends_with("/from-73746882-to-73766969-v1/ledger/epoch-170.diagnostic.jet")
            );
            assert_eq!(args[7], "--qualification-end-slot=73766969");
        }
        #[cfg(epoch170_from_73760367)]
        {
            assert_eq!(EPOCH, 170);
            assert!(args[3].starts_with(
                "--snapshot-archive=/run/horizon-170-from-73760367-v1/snapshot-73760367-"
            ));
            assert_eq!(
                args[4],
                "--epoch-hashes=/run/horizon-170-from-73760367-v1/canonical-hashes.txt"
            );
            #[cfg(not(epoch170_gap_ram_retry))]
            assert!(
                args[5].ends_with("/from-73760367-to-73766969-v1/ledger/epoch-170.diagnostic.jet")
            );
            #[cfg(all(epoch170_gap_ram_retry, not(any(epoch170_gap_ram_second, epoch170_gap_ram_third))))]
            assert!(
                UNIT.contains("-73760367-ram-")
                    && args[5].ends_with(
                        "/from-73760367-to-73766969-ram-v1/ledger/epoch-170.diagnostic.jet"
                    )
            );
            #[cfg(all(epoch170_gap_ram_retry, epoch170_gap_ram_second))]
            assert!(
                UNIT.ends_with("-73760367-ram-20261128-v2.service")
                    && args[5].ends_with(
                        "/from-73760367-to-73766969-ram-v2/ledger/epoch-170.diagnostic.jet"
                    )
            );
            #[cfg(all(epoch170_gap_ram_retry, epoch170_gap_ram_third))]
            assert!(
                UNIT.ends_with("-73760367-ram-20261128-v3.service")
                    && args[5].ends_with(
                        "/from-73760367-to-73766969-ram-v3/ledger/epoch-170.diagnostic.jet"
                    )
            );
            assert_eq!(args[7], "--qualification-end-slot=73766969");
        }
        #[cfg(epoch170_from_73766969)]
        {
            assert_eq!(EPOCH, 170);
            #[cfg(epoch170_after_checkpoint_gap)]
            assert_eq!(
                UNIT,
                "horizon-qualify-170-from-73766969-gap-20261128-v1.service"
            );
            #[cfg(not(epoch170_after_checkpoint_gap))]
            assert_eq!(
                UNIT,
                "horizon-qualify-170-from-73766969-20261127-v1.service"
            );
            assert!(args[3].starts_with(
                "--snapshot-archive=/run/horizon-170-from-73766969-v1/snapshot-73766969-"
            ));
            assert_eq!(
                args[4],
                "--epoch-hashes=/run/horizon-170-from-73766969-v1/canonical-hashes.txt"
            );
            assert!(
                args[5].ends_with("/from-73766969-to-73787145-v1/ledger/epoch-170.diagnostic.jet")
            );
            assert_eq!(args[7], "--qualification-end-slot=73787145");
        }
        #[cfg(all(
            epoch170_continuation,
            not(any(epoch170_from_73746882, epoch170_from_73760367, epoch170_from_73766969))
        ))]
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
