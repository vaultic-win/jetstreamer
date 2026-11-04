//! Fixed 60911751 restore-only comparison against mechanically preserved journal.
//! This is not a prefix manifest, continuation, archive producer or publication gate.
#[allow(dead_code)]
#[path = "../historical.rs"]
pub(crate) mod historical;

use {
    anyhow::{Context, Result, ensure},
    historical::{
        HistoricalCheckpoint, HistoricalInitialization, HistoricalRuntimeClient,
        SOLANA_V1_4_25_CANDIDATE, SnapshotInitialization, WorkerSpawn,
    },
    jetstreamer_node::{
        archive_checksum::{
            archive_file_identity, open_regular_nofollow, path_matches_archive_identity,
        },
        segment_manifest::SegmentCheckpointSummary,
    },
    serde::Deserialize,
    serde_json::{Value, json},
    sha2::{Digest, Sha256},
    solana_hash::Hash,
    std::{
        env,
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
        str::FromStr,
        time::{SystemTime, UNIX_EPOCH},
    },
};

const SLOT: u64 = 60_911_751;
const SNAPSHOT_NAME: &str =
    "snapshot-60911751-GyFbDnPnUWrFStHKfwWC98xJpmBQKjLyJ9sMf2m6MrWR.tar.zst";
const SNAPSHOT_SHA: &str = "47d5911465901975e397c570e06ccf72296db7ecd3b3b1beda710cacd3e683a1";
const WORKER_SHA: &str = "abe395d482174e490833928c7343a33d135d8572096faf873ce3103c35fe520d";
const GENESIS_SHA: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
const JOURNAL_SHA: &str = "8dfb8d6805d6b4d50ab340899447b90449c66117cc33b1af0ca6537b934a3b13";
const CLOCK_SHA: &str = "f74aacd82655179686a43c6bb137e0c0e7c7bd2955809008a745ef80f16f8be2";
const ORIGINAL_IID: &str = "b907f4e67095443cb02e9c815ee14499";
const PROTECTED_FREE: u64 = 5_153_080_892_870;
const PEAK: u64 = 128 << 30;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    worker: PathBuf,
    snapshot: PathBuf,
    ledger_directory: PathBuf,
    original_journal: Bound,
    serialized_clock: Bound,
    admission_manifest: Bound,
    admission_receipt: Bound,
    scratch_directory: PathBuf,
    output: PathBuf,
    minimum_free_bytes: u64,
}

pub(crate) fn digest(s: &str) -> Result<[u8; 32]> {
    ensure!(
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid lowercase SHA256"
    );
    let mut result = [0; 32];
    for (i, b) in result.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)?;
    }
    Ok(result)
}
pub(crate) fn bound_bytes(path: &Path, expected: &str, maximum: u64) -> Result<Vec<u8>> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical evidence path"
    );
    let mut file = open_regular_nofollow(path)?;
    let before = archive_file_identity(&file)?;
    let m = file.metadata()?;
    ensure!(
        m.uid() == 0 && m.mode() & 0o222 == 0 && m.nlink() == 1 && m.len() <= maximum,
        "evidence must be singly linked immutable root-owned file"
    );
    let mut bytes = Vec::new();
    (&mut file).take(maximum + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == m.len()
            && <[u8; 32]>::from(Sha256::digest(&bytes)) == digest(expected)?,
        "evidence digest/length mismatch"
    );
    ensure!(
        archive_file_identity(&file)? == before && path_matches_archive_identity(path, before)?,
        "evidence identity changed"
    );
    Ok(bytes)
}
fn json_file(bound: &Bound, maximum: u64) -> Result<Value> {
    Ok(serde_json::from_slice(&bound_bytes(
        &bound.path,
        &bound.sha256,
        maximum,
    )?)?)
}
fn number(v: &Value, key: &str) -> Result<u64> {
    v[key]
        .as_u64()
        .with_context(|| format!("missing integer {key}"))
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .with_context(|| format!("missing string {key}"))
}

fn expectation(journal: &Value, clock: &Value) -> Result<SegmentCheckpointSummary> {
    ensure!(
        journal["schema"] == "jetstreamer-epoch140-checkpoint-journal-observation-v1"
            && journal["producer_invocation_id"] == ORIGINAL_IID
            && journal["fields_mechanically_extracted"] == true
            && journal["source_verified_accounts_message_observed"] == true
            && journal["replay_launch_authorized"] == false
            && journal["publication_authorized"] == false,
        "wrong original journal authority"
    );
    let checkpoints = journal["checkpoints"]
        .as_array()
        .context("missing original checkpoints")?;
    ensure!(
        checkpoints.len() == 2
            && number(&checkpoints[0], "slot")? == SLOT
            && number(&checkpoints[1], "slot")? == 60_911_999,
        "original checkpoint scope changed"
    );
    let e = &checkpoints[0];
    let c = &clock["census"]["clock"];
    ensure!(
        clock["schema"] == "jetstreamer-epoch140-serialized-snapshot-clock-v1"
            && clock["input_sha256"] == SNAPSHOT_SHA
            && clock["pinned_typed_serialized_clock_only"] == true
            && clock["native_bank_restored"] == false
            && clock["replay_launch_authorized"] == false
            && clock["publication_authorized"] == false
            && c["ticks_per_slot"] == 64
            && c["hashes_per_tick"] == 12500,
        "wrong serialized clock authority"
    );
    for (left, right) in [
        ("slot", "slot"),
        ("bank_hash", "bank_hash"),
        ("last_blockhash", "last_blockhash"),
        ("capitalization", "capitalization"),
        ("transactions", "transaction_count"),
        ("tick_height", "tick_height"),
        ("complete", "complete"),
    ] {
        ensure!(
            e[left] == c[right],
            "serialized/original checkpoint {left} differs"
        );
    }
    ensure!(
        e["complete"] == true
            && text(e, "accounts_hash")? == "GyFbDnPnUWrFStHKfwWC98xJpmBQKjLyJ9sMf2m6MrWR",
        "original accounts anchor/completeness differs"
    );
    for key in ["bank_hash", "accounts_hash", "last_blockhash"] {
        Hash::from_str(text(e, key)?)?;
    }
    Ok(SegmentCheckpointSummary {
        slot: SLOT,
        bank_hash: text(e, "bank_hash")?.into(),
        accounts_hash: text(e, "accounts_hash")?.into(),
        last_blockhash: text(e, "last_blockhash")?.into(),
        capitalization: number(e, "capitalization")?,
        transaction_count: number(e, "transactions")?,
        tick_height: number(e, "tick_height")?,
        slot_complete: true,
        write_count: number(e, "writes")?,
        next_write_version: number(e, "next_write_version")?,
    })
}

pub(crate) fn compare(
    expected: &SegmentCheckpointSummary,
    actual: &HistoricalCheckpoint,
    initialized_cursor: u64,
    ticks: u64,
) -> Result<()> {
    ensure!(
        actual.slot == expected.slot
            && actual.bank_hash == Hash::from_str(&expected.bank_hash)?.to_bytes()
            && actual.accounts_hash == Hash::from_str(&expected.accounts_hash)?.to_bytes()
            && actual.last_blockhash == Hash::from_str(&expected.last_blockhash)?.to_bytes()
            && actual.capitalization == expected.capitalization
            && actual.transaction_count == expected.transaction_count
            && actual.tick_height == expected.tick_height
            && actual.slot_complete
            && ticks == 64,
        "native restored checkpoint differs from original observed checkpoint"
    );
    ensure!(actual.writes.is_empty(), "native bootstrap emitted writes");
    ensure!(
        actual.next_write_version == initialized_cursor,
        "native bootstrap advanced its local write cursor"
    );
    Ok(())
}

pub(crate) fn private_directory(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical private directory"
    );
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0,
        "private directory ownership/mode differs"
    );
    Ok(())
}
pub(crate) fn available(path: &Path) -> Result<(u64, u64)> {
    let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    let mut s = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(path.as_ptr(), s.as_mut_ptr()) } == 0,
        "statvfs failed"
    );
    let s = unsafe { s.assume_init() };
    Ok((
        s.f_bavail
            .checked_mul(s.f_frsize)
            .context("space overflow")?,
        s.f_favail,
    ))
}
pub(crate) fn write_receipt(path: &Path, value: &Value) -> Result<()> {
    let parent = path.parent().context("missing receipt parent")?;
    private_directory(parent)?;
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    ensure!(bytes.len() <= 65536, "receipt bound exceeded");
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    f.write_all(&bytes)?;
    f.sync_all()?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn validate_admission(
    value: &Value,
    manifest: &Bound,
    plan: &Plan,
    self_path: &Path,
    self_sha: &str,
    now: u64,
) -> Result<()> {
    ensure!(
        value["schema"] == "jetstreamer-historical-performance-admission-receipt-v1"
            && value["admitted"] == true
            && value["manifest_sha256"].as_str() == Some(&manifest.sha256)
            && value["remote_mutations"] == false
            && value["r2_mutations"] == false,
        "invalid admission authority"
    );
    let sampled =
        chrono::DateTime::parse_from_rfc3339(text(value, "observed_at_utc")?)?.timestamp();
    ensure!(
        sampled >= 0
            && now
                .checked_sub(sampled as u64)
                .is_some_and(|age| age <= 900),
        "stale/future admission"
    );
    ensure!(
        value["evidence"]["filesystem"] == "/home/sol"
            && number(&value["evidence"], "minimum_free_bytes")? >= plan.minimum_free_bytes
            && number(&value["evidence"], "available_bytes")? >= plan.minimum_free_bytes,
        "admission omitted full protected peak"
    );
    let files = value["evidence"]["files"]
        .as_array()
        .context("admission file census missing")?;
    for (path, sha) in [
        (self_path, self_sha),
        (&plan.worker, WORKER_SHA),
        (&plan.original_journal.path, JOURNAL_SHA),
        (&plan.serialized_clock.path, CLOCK_SHA),
    ] {
        ensure!(
            files
                .iter()
                .any(|f| f["path"].as_str() == path.to_str() && f["sha256"].as_str() == Some(sha)),
            "admission omitted exact probe/worker/source binding"
        );
    }
    Ok(())
}

fn restore(plan: &Plan, expected: &SegmentCheckpointSummary) -> Result<Value> {
    // No entry-processing API is called. Existing client owns private worker/
    // snapshot copies, exact handshake, bounded RPC, shutdown and guardian.
    let mut client = HistoricalRuntimeClient::spawn(
        SOLANA_V1_4_25_CANDIDATE,
        WorkerSpawn {
            executable: plan.worker.clone(),
            initialization: HistoricalInitialization::SnapshotArchive(SnapshotInitialization {
                ledger_path: plan.ledger_directory.clone(),
                archive_path: plan.snapshot.clone(),
                expected_slot: SLOT,
                expected_accounts_hash: Hash::from_str(&expected.accounts_hash)?.to_bytes(),
                expected_archive_sha256: Some(digest(SNAPSHOT_SHA)?),
                expected_archive_size: Some(2_741_858_751),
                scratch_parent: Some(plan.scratch_directory.clone()),
            }),
        },
    )?;
    ensure!(
        client.executable_sha256() == digest(WORKER_SHA)?,
        "executed worker digest differs"
    );
    let cursor = client.initialized().next_write_version;
    let ticks = client.initialized().ticks_per_slot;
    let actual = client.freeze_checkpoint(SLOT)?;
    let comparison = compare(expected, &actual, cursor, ticks);
    let checkpoint = json!({"slot":actual.slot,"bank_hash":Hash::new_from_array(actual.bank_hash).to_string(),
        "accounts_hash":Hash::new_from_array(actual.accounts_hash).to_string(),"last_blockhash":Hash::new_from_array(actual.last_blockhash).to_string(),
        "capitalization":actual.capitalization,"transaction_count":actual.transaction_count,"tick_height":actual.tick_height,
        "slot_complete":actual.slot_complete,"write_count":actual.writes.len(),"next_write_version":actual.next_write_version,
        "initialized_next_write_version":cursor,"initialized_ticks_per_slot":ticks});
    let shutdown = client.shutdown();
    Ok(
        json!({"native_checkpoint":checkpoint,"comparison_passed":comparison.is_ok(),
        "comparison_error":comparison.err().map(|e|e.to_string()),"shutdown_passed":shutdown.is_ok(),
        "shutdown_error":shutdown.err().map(|e|e.to_string()),"replay_entries_sent":0}),
    )
}

fn execute(plan_path: &Path, plan_sha: &str, self_sha: &str) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 1001,
        "run as isolated host replay UID 1001, not root"
    );
    let invocation = env::var("INVOCATION_ID").context("persistent systemd invocation required")?;
    ensure!(
        invocation.len() == 32
            && invocation
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid systemd invocation"
    );
    for (key, value) in [
        ("JETSTREAMER_HISTORICAL_CONTROL_TIMEOUT_SECS", "60"),
        ("JETSTREAMER_HISTORICAL_INITIALIZE_TIMEOUT_SECS", "900"),
        ("JETSTREAMER_HISTORICAL_CHECKPOINT_TIMEOUT_SECS", "600"),
        ("JETSTREAMER_HISTORICAL_REAP_TIMEOUT_SECS", "120"),
        ("SOLANA_RAYON_THREADS", "2"),
    ] {
        ensure!(
            env::var(key).ok().as_deref() == Some(value),
            "required bounded environment {key} differs"
        );
    }
    let self_path = fs::read_link("/proc/self/exe")?;
    bound_bytes(&self_path, self_sha, 256 << 20)?;
    let plan: Plan = serde_json::from_slice(&bound_bytes(plan_path, plan_sha, 1 << 20)?)?;
    ensure!(
        plan.schema == "jetstreamer-private-epoch140-native-restore-probe-plan-v1"
            && plan.minimum_free_bytes >= PROTECTED_FREE + PEAK,
        "wrong scope or insufficient full-peak protection"
    );
    ensure!(
        plan.original_journal.sha256 == JOURNAL_SHA && plan.serialized_clock.sha256 == CLOCK_SHA,
        "source evidence changed"
    );
    private_directory(&plan.scratch_directory)?;
    let parent = plan.output.parent().context("output parent missing")?;
    private_directory(parent)?;
    ensure!(
        plan.output.is_absolute()
            && !plan.output.starts_with(&plan.scratch_directory)
            && fs::symlink_metadata(&plan.output)
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
            && fs::read_dir(&plan.scratch_directory)?.next().is_none(),
        "attempt must be fresh and disjoint"
    );
    let m = fs::symlink_metadata(&plan.ledger_directory)?;
    ensure!(
        plan.ledger_directory.canonicalize()? == plan.ledger_directory
            && m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o222 == 0,
        "ledger must be sealed/root-owned"
    );
    ensure!(
        fs::symlink_metadata(plan.ledger_directory.join("genesis.bin"))
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "alternate genesis must not shadow archive"
    );
    ensure!(
        plan.snapshot.file_name().and_then(|s| s.to_str()) == Some(SNAPSHOT_NAME),
        "wrong snapshot filename"
    );
    let snapshot_metadata = fs::symlink_metadata(&plan.snapshot)?;
    ensure!(
        plan.snapshot.parent() == Some(plan.ledger_directory.as_path())
            && plan.snapshot.canonicalize()? == plan.snapshot
            && snapshot_metadata.is_file()
            && snapshot_metadata.uid() == 0
            && snapshot_metadata.mode() & 0o222 == 0
            && snapshot_metadata.nlink() == 1
            && snapshot_metadata.len() == 2_741_858_751,
        "snapshot must be the exact immutable direct sealed input member"
    );
    let filesystem_device = fs::metadata("/home/sol")?.dev();
    ensure!(
        fs::metadata(&plan.scratch_directory)?.dev() == filesystem_device
            && fs::metadata(parent)?.dev() == filesystem_device,
        "scratch/output must use the admitted campaign filesystem"
    );
    bound_bytes(&plan.worker, WORKER_SHA, 256 << 20)?;
    let genesis = plan.ledger_directory.join("genesis.tar.bz2");
    bound_bytes(&genesis, GENESIS_SHA, 10 << 20)?;
    let journal = json_file(&plan.original_journal, 65536)?;
    let clock = json_file(&plan.serialized_clock, 65536)?;
    let expected = expectation(&journal, &clock)?;
    bound_bytes(
        &plan.admission_manifest.path,
        &plan.admission_manifest.sha256,
        4 << 20,
    )?;
    let admission = json_file(&plan.admission_receipt, 4 << 20)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    validate_admission(
        &admission,
        &plan.admission_manifest,
        &plan,
        &self_path,
        self_sha,
        now,
    )?;
    let (free, inodes) = available(&plan.scratch_directory)?;
    ensure!(
        free >= plan.minimum_free_bytes && inodes >= 1_000_000,
        "free bytes/inodes below complete restore admission"
    );
    let vmas = fs::read_to_string("/proc/sys/vm/max_map_count")?
        .trim()
        .parse::<u64>()?;
    ensure!(vmas >= 4_194_304, "host VMA ceiling below bound");
    let outcome = restore(&plan, &expected);
    let passed = outcome
        .as_ref()
        .is_ok_and(|v| v["comparison_passed"] == true && v["shutdown_passed"] == true);
    let error = outcome
        .as_ref()
        .err()
        .map(|e| e.to_string().chars().take(2048).collect::<String>());
    let result = outcome.ok();
    let after = available(&plan.scratch_directory)?;
    let receipt = json!({"schema":"jetstreamer-private-epoch140-native-restore-probe-v1","invocation_id":invocation,
        "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),"plan":plan_path,"plan_sha256":plan_sha,"self_sha256":self_sha,
        "original_journal_sha256":JOURNAL_SHA,"serialized_clock_sha256":CLOCK_SHA,"worker_sha256":WORKER_SHA,"snapshot_sha256":SNAPSHOT_SHA,
        "original_producer_cursor":expected.next_write_version,"native_result":result,"error":error,
        "passed":passed && after.0>=PROTECTED_FREE,"available_bytes_before":free,"available_bytes_after":after.0,"available_inodes_before":inodes,
        "archive_prefix_verified":false,"prefix_manifest_created":false,"suffix_generated":false,"replay_entries_sent":0,
        "native_consensus_comparison_only":true,"executing_suffix_must_repeat_native_tuple_check":true,
        "replay_launch_authorized":false,"assembly_authorized":false,"publication_authorized":false,"local_retirement_authorized":false,
        "remote_mutations":false,"r2_mutations":false});
    bound_bytes(&genesis, GENESIS_SHA, 10 << 20)?;
    json_file(&plan.original_journal, 65536)?;
    json_file(&plan.serialized_clock, 65536)?;
    write_receipt(&plan.output, &receipt)?;
    ensure!(
        passed && after.0 >= PROTECTED_FREE,
        "native restore comparison failed; private outcome preserved"
    );
    Ok(())
}

fn main() {
    let a: Vec<_> = env::args().skip(1).collect();
    let result = if a.len() == 5 && a[1] == "--plan-sha256" && a[3] == "--self-sha256" {
        execute(Path::new(&a[0]), &a[2], &a[4])
    } else {
        Err(anyhow::anyhow!(
            "usage: PLAN --plan-sha256 HEX --self-sha256 HEX"
        ))
    };
    if let Err(e) = result {
        eprintln!("native restore-only probe failed: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn expected() -> SegmentCheckpointSummary {
        SegmentCheckpointSummary {
            slot: SLOT,
            bank_hash: Hash::new_from_array([1; 32]).to_string(),
            accounts_hash: "GyFbDnPnUWrFStHKfwWC98xJpmBQKjLyJ9sMf2m6MrWR".into(),
            last_blockhash: Hash::new_from_array([3; 32]).to_string(),
            capitalization: 5,
            transaction_count: 6,
            tick_height: (SLOT + 1) * 64,
            slot_complete: true,
            write_count: 20,
            next_write_version: 111,
        }
    }
    fn actual() -> HistoricalCheckpoint {
        let e = expected();
        HistoricalCheckpoint {
            slot: e.slot,
            bank_hash: Hash::from_str(&e.bank_hash).unwrap().to_bytes(),
            accounts_hash: Hash::from_str(&e.accounts_hash).unwrap().to_bytes(),
            last_blockhash: Hash::from_str(&e.last_blockhash).unwrap().to_bytes(),
            capitalization: e.capitalization,
            transaction_count: e.transaction_count,
            tick_height: e.tick_height,
            slot_complete: true,
            writes: vec![],
            next_write_version: 222,
        }
    }
    #[test]
    fn native_comparison_keeps_validator_cursors_independent() {
        assert_ne!(expected().next_write_version, actual().next_write_version);
        compare(&expected(), &actual(), 222, 64).unwrap();
    }
    #[test]
    fn all_native_consensus_clock_and_local_cursor_checks_are_mandatory() {
        let mutations: [fn(&mut HistoricalCheckpoint); 8] = [
            |v| v.slot += 1,
            |v| v.bank_hash[0] ^= 1,
            |v| v.accounts_hash[0] ^= 1,
            |v| v.last_blockhash[0] ^= 1,
            |v| v.capitalization += 1,
            |v| v.transaction_count += 1,
            |v| v.tick_height += 1,
            |v| v.slot_complete = false,
        ];
        for mutate in mutations {
            let mut a = actual();
            mutate(&mut a);
            assert!(compare(&expected(), &a, 222, 64).is_err());
        }
        assert!(compare(&expected(), &actual(), 223, 64).is_err());
        assert!(compare(&expected(), &actual(), 222, 32).is_err());
    }
    #[test]
    fn bootstrap_writes_are_not_cursor_rebasing() {
        let mut a = actual();
        a.writes.push(historical::HistoricalAccountWrite {
            slot: SLOT,
            write_version: 222,
            transaction_signature: None,
            pubkey: [0; 32],
            lamports: 0,
            owner: [0; 32],
            executable: false,
            rent_epoch: 0,
            data: vec![],
            stored_hash: [0; 32],
        });
        assert!(compare(&expected(), &a, 222, 64).is_err());
    }
    #[test]
    fn no_manifest_or_replay_override_in_plan() {
        assert!(
            serde_json::from_value::<Plan>(json!({"schema":"test","allow_replay":true})).is_err()
        );
        for bad in ["", "00", &"A".repeat(64), &"g".repeat(64)] {
            assert!(digest(bad).is_err());
        }
    }

    fn sources() -> (Value, Value) {
        let e = expected();
        let first = json!({"slot":e.slot,"bank_hash":e.bank_hash,"accounts_hash":e.accounts_hash,
            "last_blockhash":e.last_blockhash,"capitalization":e.capitalization,"transactions":e.transaction_count,
            "tick_height":e.tick_height,"complete":true,"writes":e.write_count,"next_write_version":e.next_write_version});
        let journal = json!({"schema":"jetstreamer-epoch140-checkpoint-journal-observation-v1",
            "producer_invocation_id":ORIGINAL_IID,"fields_mechanically_extracted":true,
            "source_verified_accounts_message_observed":true,"replay_launch_authorized":false,
            "publication_authorized":false,"checkpoints":[first,{"slot":60911999}]});
        let clock = json!({"schema":"jetstreamer-epoch140-serialized-snapshot-clock-v1","input_sha256":SNAPSHOT_SHA,
            "pinned_typed_serialized_clock_only":true,"native_bank_restored":false,
            "replay_launch_authorized":false,"publication_authorized":false,"census":{"clock":{
                "slot":e.slot,"bank_hash":e.bank_hash,"last_blockhash":e.last_blockhash,"capitalization":e.capitalization,
                "transaction_count":e.transaction_count,"tick_height":e.tick_height,"complete":true,
                "ticks_per_slot":64,"hashes_per_tick":12500}}});
        (journal, clock)
    }

    #[test]
    fn source_expectations_are_mechanical_and_cannot_borrow_another_checkpoint() {
        let (j, c) = sources();
        assert_eq!(expectation(&j, &c).unwrap(), expected());
        for (key, v) in [
            ("schema", json!("another")),
            ("producer_invocation_id", json!("a".repeat(32))),
            ("fields_mechanically_extracted", json!(false)),
            ("source_verified_accounts_message_observed", json!(false)),
            ("replay_launch_authorized", json!(true)),
            ("publication_authorized", json!(true)),
        ] {
            let mut bad = j.clone();
            bad[key] = v;
            assert!(expectation(&bad, &c).is_err(), "{key}");
        }
        for key in [
            "slot",
            "bank_hash",
            "last_blockhash",
            "capitalization",
            "transactions",
            "tick_height",
            "complete",
            "accounts_hash",
        ] {
            let mut bad = j.clone();
            bad["checkpoints"][0][key] = json!("wrong");
            assert!(expectation(&bad, &c).is_err(), "{key}");
        }
        for (key, v) in [
            ("schema", json!("another")),
            ("input_sha256", json!("0".repeat(64))),
            ("pinned_typed_serialized_clock_only", json!(false)),
            ("native_bank_restored", json!(true)),
            ("replay_launch_authorized", json!(true)),
            ("publication_authorized", json!(true)),
        ] {
            let mut bad = c.clone();
            bad[key] = v;
            assert!(expectation(&j, &bad).is_err(), "{key}");
        }
        for key in ["ticks_per_slot", "hashes_per_tick"] {
            let mut bad = c.clone();
            bad["census"]["clock"][key] = json!(1);
            assert!(expectation(&j, &bad).is_err());
        }
    }

    #[test]
    fn admission_must_be_fresh_and_bind_the_exact_sources_worker_and_probe() {
        let b = |path: &str, sha: &str| Bound {
            path: path.into(),
            sha256: sha.into(),
        };
        let plan = Plan {
            schema: "test".into(),
            worker: "/sealed/worker".into(),
            snapshot: "/sealed/snapshot".into(),
            ledger_directory: "/sealed".into(),
            original_journal: b("/sealed/journal", JOURNAL_SHA),
            serialized_clock: b("/sealed/clock", CLOCK_SHA),
            admission_manifest: b("/sealed/manifest", &"1".repeat(64)),
            admission_receipt: b("/sealed/admitted", &"2".repeat(64)),
            scratch_directory: "/private/scratch".into(),
            output: "/private/result".into(),
            minimum_free_bytes: PROTECTED_FREE + PEAK,
        };
        let path = Path::new("/sealed/probe");
        let sha = "3".repeat(64);
        let files = [
            (path, sha.as_str()),
            (plan.worker.as_path(), WORKER_SHA),
            (plan.original_journal.path.as_path(), JOURNAL_SHA),
            (plan.serialized_clock.path.as_path(), CLOCK_SHA),
        ]
        .iter()
        .map(|(path, sha)| json!({"path":path,"sha256":sha}))
        .collect::<Vec<_>>();
        let value = json!({"schema":"jetstreamer-historical-performance-admission-receipt-v1","admitted":true,
            "manifest_sha256":plan.admission_manifest.sha256,"remote_mutations":false,"r2_mutations":false,
            "observed_at_utc":"1970-01-01T00:16:40+00:00","evidence":{"filesystem":"/home/sol",
                "minimum_free_bytes":plan.minimum_free_bytes,"available_bytes":plan.minimum_free_bytes,"files":files}});
        validate_admission(&value, &plan.admission_manifest, &plan, path, &sha, 1001).unwrap();
        assert!(
            validate_admission(&value, &plan.admission_manifest, &plan, path, &sha, 999).is_err()
        );
        assert!(
            validate_admission(&value, &plan.admission_manifest, &plan, path, &sha, 1901).is_err()
        );
        for i in 0..4 {
            let mut bad = value.clone();
            bad["evidence"]["files"].as_array_mut().unwrap().remove(i);
            assert!(
                validate_admission(&bad, &plan.admission_manifest, &plan, path, &sha, 1001)
                    .is_err()
            );
        }
        let mut bad = value.clone();
        bad["manifest_sha256"] = json!("0".repeat(64));
        assert!(
            validate_admission(&bad, &plan.admission_manifest, &plan, path, &sha, 1001).is_err()
        );
        let mut bad = value.clone();
        bad["evidence"]["minimum_free_bytes"] = json!(plan.minimum_free_bytes - 1);
        assert!(
            validate_admission(&bad, &plan.admission_manifest, &plan, path, &sha, 1001).is_err()
        );
    }
}
