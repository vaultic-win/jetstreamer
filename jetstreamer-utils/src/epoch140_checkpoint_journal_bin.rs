//! Fixed, bounded capture of original epoch 140 checkpoint observations.
//! This is primary-source preservation, not a recovery manifest or launch gate.
#[allow(dead_code)]
mod epoch141_ledger_common;

use {
    anyhow::{Context, Result, ensure},
    base64::{Engine, engine::general_purpose::STANDARD},
    epoch141_ledger_common::{bound_file, is_sha, sha, wait_bounded, write_receipt},
    serde::{Deserialize, Serialize},
    serde_json::json,
    std::{
        collections::BTreeSet,
        env,
        fs::File,
        io::Read,
        path::PathBuf,
        process::{Command, Stdio},
        thread,
        time::{Duration, SystemTime, UNIX_EPOCH},
    },
};

const IID: &str = "b907f4e67095443cb02e9c815ee14499";
const UNIT: &str = "jetstreamer-root-sweep-e136-147-t4-20261014-v1-r2-e140-143-lane-j-2.service";
const EXE: &str =
    "/usr/local/lib/jetstreamer/deploy-epochs136-147-target4-20261011-v2/jetstreamer-node";
const BOOT: &str = "763ea84ca81f4dddad364b1ea2ba36dd";
const ACCOUNTS: &str = "GyFbDnPnUWrFStHKfwWC98xJpmBQKjLyJ9sMf2m6MrWR";
const MAX_CAPTURE: usize = 64 * 1024;
const SINCE: &str = "2026-10-18 23:27:00 UTC";
const UNTIL: &str = "2026-10-18 23:33:00 UTC";
const PATTERN: &str = "historical checkpoint slot=60911751|historical checkpoint slot=60911999|verified legacy accounts hash at slot 60911751";
const BOOTSTRAP_SINCE: &str = "2026-10-14 14:14:00 UTC";
const BOOTSTRAP_UNTIL: &str = "2026-10-14 14:17:00 UTC";
const BOOTSTRAP_PATTERN: &str =
    "historical checkpoint slot=60479583|verified legacy accounts hash at slot 60479583";
const BOOTSTRAP_ACCOUNTS: &str = "J8K4RVWeRvQavXqwbhA58KCWHKWGaRENqALCed65rfkZ";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    journalctl_sha256: String,
    output_receipt: PathBuf,
    #[serde(default)]
    capture_original_bootstrap: bool,
}

#[derive(Deserialize)]
struct Record {
    #[serde(rename = "_SYSTEMD_INVOCATION_ID")]
    invocation: String,
    #[serde(rename = "_SYSTEMD_UNIT")]
    unit: String,
    #[serde(rename = "_BOOT_ID")]
    boot: String,
    #[serde(rename = "_PID")]
    pid: String,
    #[serde(rename = "_EXE")]
    executable: String,
    #[serde(rename = "__REALTIME_TIMESTAMP")]
    timestamp: String,
    #[serde(rename = "__CURSOR")]
    cursor: String,
    #[serde(rename = "MESSAGE")]
    message: String,
}

#[derive(Debug, Serialize, PartialEq)]
struct Checkpoint {
    slot: u64,
    bank_hash: String,
    accounts_hash: String,
    last_blockhash: String,
    capitalization: u64,
    transactions: u64,
    tick_height: u64,
    complete: bool,
    writes: u64,
    next_write_version: u64,
    journal_cursor: String,
    journal_timestamp_micros: u64,
    journal_message: String,
}

fn number(s: &str) -> Result<u64> {
    let n = s.parse::<u64>()?;
    ensure!(n.to_string() == s, "noncanonical integer");
    Ok(n)
}

fn hash(s: &str) -> Result<String> {
    let bytes = bs58::decode(s)
        .into_vec()
        .map_err(|e| anyhow::anyhow!("invalid base58 hash: {e}"))?;
    ensure!(
        bytes.len() == 32 && bs58::encode(&bytes).into_string() == s,
        "not a canonical32-byte hash"
    );
    Ok(s.to_owned())
}

fn checkpoint(record: &Record, timestamp: u64) -> Result<Checkpoint> {
    let (prefix, tail) = record
        .message
        .split_once(" historical checkpoint ")
        .context("checkpoint marker missing")?;
    ensure!(
        prefix.starts_with('[') && prefix.ends_with(" INFO  jetstreamer_node::historical_replay]"),
        "unexpected checkpoint emitter"
    );
    let fields = tail.split(' ').collect::<Vec<_>>();
    let keys = [
        "slot",
        "bank_hash",
        "accounts_hash",
        "last_blockhash",
        "capitalization",
        "transactions",
        "tick_height",
        "complete",
        "writes",
        "next_write_version",
    ];
    ensure!(fields.len() == keys.len(), "wrong checkpoint field count");
    let values = keys
        .iter()
        .zip(fields)
        .map(|(key, field)| {
            field
                .strip_prefix(&format!("{key}="))
                .context("checkpoint field missing/reordered")
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(values[7] == "true", "checkpoint is not complete");
    Ok(Checkpoint {
        slot: number(values[0])?,
        bank_hash: hash(values[1])?,
        accounts_hash: hash(values[2])?,
        last_blockhash: hash(values[3])?,
        capitalization: number(values[4])?,
        transactions: number(values[5])?,
        tick_height: number(values[6])?,
        complete: true,
        writes: number(values[8])?,
        next_write_version: number(values[9])?,
        journal_cursor: record.cursor.clone(),
        journal_timestamp_micros: timestamp,
        journal_message: record.message.clone(),
    })
}

fn extract(bytes: &[u8]) -> Result<Vec<Checkpoint>> {
    ensure!(bytes.len() <= MAX_CAPTURE, "journal byte limit exceeded");
    let lines = std::str::from_utf8(bytes)?.lines().collect::<Vec<_>>();
    ensure!(
        lines.len() == 3,
        "expected exactly 3 primary journal records"
    );
    let mut cursors = BTreeSet::new();
    let mut checkpoints = Vec::new();
    let mut verified = None;
    let mut previous_timestamp = 0;
    for line in lines {
        let r: Record = serde_json::from_str(line)?;
        let timestamp = number(&r.timestamp)?;
        ensure!(
            r.invocation == IID
                && r.unit == UNIT
                && r.boot == BOOT
                && r.pid == "828090"
                && r.executable == EXE,
            "original producer identity mismatch"
        );
        ensure!(
            (1_792_366_020_000_000..1_792_366_380_000_000).contains(&timestamp)
                && timestamp > previous_timestamp
                && !r.cursor.is_empty()
                && cursors.insert(r.cursor.clone()),
            "journal ordering/window/cursor mismatch"
        );
        previous_timestamp = timestamp;
        if r.message
            .ends_with(" INFO  jetstreamer_node] verified legacy accounts hash at slot 60911751")
        {
            ensure!(
                r.message.starts_with('[') && verified.is_none() && checkpoints.is_empty(),
                "unexpected verified-accounts record"
            );
            verified = Some(timestamp);
        } else {
            let c = checkpoint(&r, timestamp)?;
            let expected_slot = if checkpoints.is_empty() {
                60_911_751
            } else {
                60_911_999
            };
            ensure!(
                c.slot == expected_slot && checkpoints.len() < 2,
                "checkpoint scope/duplication mismatch"
            );
            if checkpoints.is_empty() {
                ensure!(
                    verified.is_some() && c.accounts_hash == ACCOUNTS,
                    "missing verified source checkpoint or accounts anchor mismatch"
                );
            }
            checkpoints.push(c);
        }
    }
    ensure!(
        verified.is_some() && checkpoints.len() == 2,
        "incomplete checkpoint capture"
    );
    Ok(checkpoints)
}

fn capture<R: Read>(pipe: R) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    pipe.take(MAX_CAPTURE as u64 + 1).read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn extract_bootstrap(bytes: &[u8]) -> Result<Vec<Checkpoint>> {
    #[derive(Deserialize)]
    struct BootstrapRecord {
        #[serde(flatten)]
        record: Record,
        #[serde(rename = "__SEQNUM")]
        sequence: String,
        #[serde(rename = "__SEQNUM_ID")]
        sequence_id: String,
    }
    ensure!(bytes.len() <= MAX_CAPTURE, "journal byte limit exceeded");
    let lines = std::str::from_utf8(bytes)?.lines().collect::<Vec<_>>();
    ensure!(
        lines.len() == 2,
        "expected exactly 2 original bootstrap records"
    );
    let mut previous_time = 0;
    let mut previous_sequence = 0;
    let mut cursors = BTreeSet::new();
    let mut result = Vec::new();
    for (index, line) in lines.into_iter().enumerate() {
        let source: BootstrapRecord = serde_json::from_str(line)?;
        let r = source.record;
        let time = number(&r.timestamp)?;
        let sequence = number(&source.sequence)?;
        ensure!(
            r.invocation == IID
                && r.unit == UNIT
                && r.boot == BOOT
                && r.pid == "828090"
                && r.executable == EXE
                && source.sequence_id == "7f76387dd96140468b39dcf01e726fea"
                && (1_791_987_240_000_000..1_791_987_420_000_000).contains(&time)
                && time >= previous_time
                && sequence > previous_sequence
                && !r.cursor.is_empty()
                && cursors.insert(r.cursor.clone()),
            "original bootstrap identity/window/order mismatch"
        );
        previous_time = time;
        previous_sequence = sequence;
        if index == 0 {
            ensure!(
                r.message.starts_with('[')
                    && r.message.ends_with(
                        " INFO  jetstreamer_node] verified legacy accounts hash at slot 60479583"
                    ),
                "missing original verified bootstrap accounts message"
            );
        } else {
            let c = checkpoint(&r, time)?;
            ensure!(
                c.slot == 60_479_583
                    && c.accounts_hash == BOOTSTRAP_ACCOUNTS
                    && c.writes == 0
                    && c.tick_height == (c.slot + 1) * 64,
                "original bootstrap scope/accounts/clock/write mismatch"
            );
            result.push(c);
        }
    }
    Ok(result)
}

fn journal(original_bootstrap: bool) -> Result<Vec<u8>> {
    let (since, until, pattern) = if original_bootstrap {
        (BOOTSTRAP_SINCE, BOOTSTRAP_UNTIL, BOOTSTRAP_PATTERN)
    } else {
        (SINCE, UNTIL, PATTERN)
    };
    let mut child = Command::new("/usr/bin/journalctl")
        .args([
            format!("_SYSTEMD_INVOCATION_ID={IID}"),
            "--since".into(),
            since.into(),
            "--until".into(),
            until.into(),
            format!("--grep={pattern}"),
            "--no-pager".into(),
            "--no-hostname".into(),
            "-o".into(),
            "json".into(),
        ])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let out = child.stdout.take().context("journal stdout missing")?;
    let err = child.stderr.take().context("journal stderr missing")?;
    let stdout = thread::spawn(move || capture(out));
    let stderr = thread::spawn(move || capture(err));
    let status = wait_bounded(&mut child, Duration::from_secs(30))?;
    let out = stdout
        .join()
        .map_err(|_| anyhow::anyhow!("journal reader panicked"))??;
    let err = stderr
        .join()
        .map_err(|_| anyhow::anyhow!("journal error reader panicked"))??;
    ensure!(
        status.success() && err.is_empty() && out.len() <= MAX_CAPTURE,
        "journal capture failed, warned or exceeded bound"
    );
    Ok(out)
}

fn run() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    let args = env::args().skip(1).collect::<Vec<_>>();
    ensure!(
        args.len() == 5 && args[1] == "--plan-sha256" && args[3] == "--self-sha256",
        "usage: PLAN --plan-sha256 HEX --self-sha256 HEX"
    );
    ensure!(is_sha(&args[4]), "invalid self digest");
    let mut running = Vec::new();
    File::open("/proc/self/exe")?
        .take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut running)?;
    ensure!(
        running.len() <= 64 * 1024 * 1024 && sha(&running) == args[4],
        "self hash mismatch"
    );
    let plan_path = PathBuf::from(&args[0]);
    let plan: Plan = serde_json::from_slice(&bound_file(&plan_path, &args[2], 16384, true)?)?;
    ensure!(
        plan.schema == "jetstreamer-epoch140-checkpoint-journal-plan-v1",
        "unsupported capture plan"
    );
    let journalctl = PathBuf::from("/usr/bin/journalctl");
    // No metadata-only executable trust: read/hash the actual pinned regular file.
    bound_file(
        &journalctl,
        &plan.journalctl_sha256,
        16 * 1024 * 1024,
        false,
    )?;
    let bytes = journal(plan.capture_original_bootstrap)?;
    let checkpoints = if plan.capture_original_bootstrap {
        extract_bootstrap(&bytes)?
    } else {
        extract(&bytes)?
    };
    let (schema, since, until, pattern) = if plan.capture_original_bootstrap {
        (
            "jetstreamer-epoch140-bootstrap-journal-observation-v1",
            BOOTSTRAP_SINCE,
            BOOTSTRAP_UNTIL,
            BOOTSTRAP_PATTERN,
        )
    } else {
        (
            "jetstreamer-epoch140-checkpoint-journal-observation-v1",
            SINCE,
            UNTIL,
            PATTERN,
        )
    };
    bound_file(
        &journalctl,
        &plan.journalctl_sha256,
        16 * 1024 * 1024,
        false,
    )?;
    let receipt = json!({
        "schema":schema,
        "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        "plan":plan_path,"plan_sha256":args[2],"self_sha256":args[4],
        "producer_invocation_id":IID,"producer_unit":UNIT,"producer_executable":EXE,
        "journalctl_sha256":plan.journalctl_sha256,"since_utc":since,"until_utc":until,
        "grep_pattern":pattern,"raw_journal_base64":STANDARD.encode(&bytes),
        "raw_journal_sha256":sha(&bytes),"raw_journal_bytes":bytes.len(),
        "checkpoints":checkpoints,"fields_mechanically_extracted":true,
        "source_verified_accounts_message_observed":true,
        "independent_canonical_terminal_accounts_hash_proven":false,
        "native_restore_tuple_compared":false,"snapshot_clock_authenticated":false,
        "recovery_manifest_created":false,"canonical_tail_divergence_proven":false,
        "archive_modified":false,"replay_launch_authorized":false,
        "publication_authorized":false,"remote_mutations":false,"r2_mutations":false
    });
    write_receipt(&plan.output_receipt, &receipt)?;
    println!("captured exact original checkpoint journal; recovery/publication unauthorized");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record(message: &str, seq: u64) -> serde_json::Value {
        json!({"_SYSTEMD_INVOCATION_ID":IID,"_SYSTEMD_UNIT":UNIT,"_BOOT_ID":BOOT,
            "_PID":"828090","_EXE":EXE,"__REALTIME_TIMESTAMP":(1_792_366_090_000_000+seq).to_string(),
            "__CURSOR":format!("cursor{seq}"),"MESSAGE":message})
    }
    fn fixtures() -> Vec<serde_json::Value> {
        let hash = bs58::encode([7u8; 32]).into_string();
        let line = |slot, accounts: &str| {
            format!(
                "[2026-10-18T23:28:10Z INFO  jetstreamer_node::historical_replay] historical checkpoint slot={slot} bank_hash={hash} accounts_hash={accounts} last_blockhash={hash} capitalization=488588165537070640 transactions=9398636535 tick_height=3898352128 complete=true writes=20 next_write_version=28029693043"
            )
        };
        vec![
            record(
                "[2026-10-18T23:28:10Z INFO  jetstreamer_node] verified legacy accounts hash at slot 60911751",
                1,
            ),
            record(&line(60_911_751, ACCOUNTS), 2),
            record(&line(60_911_999, &hash), 3),
        ]
    }
    fn bytes(records: &[serde_json::Value]) -> Vec<u8> {
        records
            .iter()
            .map(|v| format!("{v}\n"))
            .collect::<String>()
            .into_bytes()
    }
    #[test]
    fn bootstrap_capture_preserves_u64_and_orders_equal_microsecond_records() {
        let hash = bs58::encode([7u8; 32]).into_string();
        let mut r = vec![
            record(
                "[2026-10-14T14:15:27Z INFO  jetstreamer_node] verified legacy accounts hash at slot 60479583",
                1,
            ),
            record(
                &format!(
                    "[2026-10-14T14:15:27Z INFO  jetstreamer_node::historical_replay] historical checkpoint slot=60479583 bank_hash={hash} accounts_hash={BOOTSTRAP_ACCOUNTS} last_blockhash={hash} capitalization=488588429281363761 transactions=9214190271 tick_height=3870693376 complete=true writes=0 next_write_version=27312586702"
                ),
                2,
            ),
        ];
        for (index, v) in r.iter_mut().enumerate() {
            v["__REALTIME_TIMESTAMP"] = json!("1791987327903144");
            v["__SEQNUM"] = json!((index + 1).to_string());
            v["__SEQNUM_ID"] = json!("7f76387dd96140468b39dcf01e726fea");
        }
        let c = extract_bootstrap(&bytes(&r)).unwrap();
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].capitalization, 488_588_429_281_363_761);
        assert_eq!(c[0].slot, 60_479_583);
        assert_eq!(c[0].next_write_version, 27_312_586_702);
        assert_eq!(c[0].writes, 0);
        for (key, value) in [
            ("__SEQNUM", json!("1")),
            ("__SEQNUM_ID", json!("foreign")),
            ("_SYSTEMD_INVOCATION_ID", json!("foreign")),
            ("__REALTIME_TIMESTAMP", json!("1792366090000000")),
            ("__CURSOR", r[0]["__CURSOR"].clone()),
        ] {
            let mut bad = r.clone();
            bad[1][key] = value;
            assert!(extract_bootstrap(&bytes(&bad)).is_err(), "{key}");
        }
        let mut bad = r.clone();
        bad.swap(0, 1);
        assert!(extract_bootstrap(&bytes(&bad)).is_err());
        assert!(extract(&bytes(&r)).is_err());
        assert!(extract_bootstrap(&bytes(&fixtures())).is_err());
        let mut bad = r;
        bad[1]["MESSAGE"] = json!(
            bad[1]["MESSAGE"]
                .as_str()
                .unwrap()
                .replace("writes=0", "writes=1")
        );
        assert!(extract_bootstrap(&bytes(&bad)).is_err());
    }

    #[test]
    fn bootstrap_scope_is_explicit_and_old_plan_default_is_unchanged() {
        let mut v = json!({"schema":"jetstreamer-epoch140-checkpoint-journal-plan-v1", "journalctl_sha256":"a".repeat(64),"output_receipt":"/private/out.json"});
        assert!(
            !serde_json::from_value::<Plan>(v.clone())
                .unwrap()
                .capture_original_bootstrap
        );
        v["capture_original_bootstrap"] = json!(true);
        assert!(
            serde_json::from_value::<Plan>(v.clone())
                .unwrap()
                .capture_original_bootstrap
        );
        v["replay_launch_authorized"] = json!(true);
        assert!(serde_json::from_value::<Plan>(v).is_err());
    }

    #[test]
    fn extracts_all_fields_without_handwritten_consensus_tuple() {
        let c = extract(&bytes(&fixtures())).unwrap();
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].slot, 60_911_751);
        assert_eq!(c[0].accounts_hash, ACCOUNTS);
        assert_eq!(c[0].writes, 20);
        assert_eq!(c[0].next_write_version, 28_029_693_043);
        assert_eq!(c[0].capitalization, 488_588_165_537_070_640);
        assert_eq!(c[0].transactions, 9_398_636_535);
        assert_eq!(c[0].tick_height, 3_898_352_128);
    }
    #[test]
    fn rejects_changed_identity_window_order_missing_and_duplicate_records() {
        for key in [
            "_SYSTEMD_INVOCATION_ID",
            "_SYSTEMD_UNIT",
            "_BOOT_ID",
            "_PID",
            "_EXE",
            "__REALTIME_TIMESTAMP",
            "__CURSOR",
        ] {
            let mut r = fixtures();
            r[1][key] = json!("");
            assert!(extract(&bytes(&r)).is_err(), "{key}");
        }
        let mut r = fixtures();
        r.swap(1, 2);
        assert!(extract(&bytes(&r)).is_err());
        let mut r = fixtures();
        r[2] = r[1].clone();
        assert!(extract(&bytes(&r)).is_err());
        assert!(extract(&bytes(&fixtures()[1..])).is_err());
        let mut r = fixtures();
        r.push(r[0].clone());
        assert!(extract(&bytes(&r)).is_err());
        let mut r = fixtures();
        r[0]["__REALTIME_TIMESTAMP"] = json!("1792366380000000");
        assert!(extract(&bytes(&r)).is_err());
    }
    #[test]
    fn rejects_malformed_hashes_counts_fields_and_trailing_data() {
        for (old, new) in [
            ("slot=60911751", "slot=60911750"),
            ("complete=true", "complete=false"),
            ("writes=20", "writes=020"),
            ("writes=20", "writes=-1"),
            (
                "next_write_version=28029693043",
                "next_write_version=18446744073709551616",
            ),
            ("bank_hash=", "unknown="),
            (ACCOUNTS, "1111"),
        ] {
            let mut r = fixtures();
            r[1]["MESSAGE"] = json!(r[1]["MESSAGE"].as_str().unwrap().replace(old, new));
            assert!(extract(&bytes(&r)).is_err(), "{old}");
        }
        let mut r = fixtures();
        r[1]["MESSAGE"] = json!(format!("{} extra=1", r[1]["MESSAGE"].as_str().unwrap()));
        assert!(extract(&bytes(&r)).is_err());
        assert!(extract(&vec![b' '; MAX_CAPTURE + 1]).is_err());
    }
}
