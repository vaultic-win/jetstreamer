//! Private, restore-only comparison of the exact epoch203 capped-shrink prefix.
//! No replay entries, suffix, archive assembly, canonical sidecar or publication.
#[allow(dead_code)]
#[path = "jetstreamer-epoch140-native-restore-probe.rs"]
mod baseline;

use {
    anyhow::{Context, Result, ensure},
    baseline::{
        available, bound_bytes, compare, digest,
        historical::{
            HistoricalInitialization, HistoricalRuntimeClient, SOLANA_V1_6_16_CANDIDATE,
            SnapshotInitialization, WorkerSpawn,
        },
        private_directory, write_receipt,
    },
    jetstreamer_node::segment_manifest::{
        HistoricalSegmentManifest, SEGMENT_MANIFEST_CONTENT_ENCODING, SegmentRuntimeAdmission,
        sha256_hex_string,
    },
    serde::{Deserialize, Serialize},
    serde_json::{Value, json},
    solana_hash::Hash,
    std::{
        env, fs,
        fs::{File, OpenOptions},
        os::{
            fd::AsRawFd,
            unix::fs::{MetadataExt, OpenOptionsExt},
        },
        path::{Path, PathBuf},
        process::Command,
        str::FromStr,
        time::{Instant, SystemTime, UNIX_EPOCH},
    },
};

const SLOT: u64 = 88_127_580;
const START: u64 = 87_696_000;
const WORKER: &str = "4aeca56378a4bb2c55d0e590c1e334c4afa6a375a2c0d94894b412bea261f1cc";
const SNAPSHOT: &str = "d3114597ce25c3efaa4a96899ab3e9437c51cb9086d4166639f0ad2ae0613ee6";
const SNAPSHOT_SIZE: u64 = 8_215_471_895;
const SNAPSHOT_NAME: &str =
    "snapshot-88127580-4SeHmKHQrHot4gwifo1bnvDKXZwGELk2vSenotTx9oqf.tar.zst";
const ROOT_HASH: &str = "4SeHmKHQrHot4gwifo1bnvDKXZwGELk2vSenotTx9oqf";
const GENESIS: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
const PREFIX: &str = "/home/ubuntu/.jetstreamer-private/shrink-root-prefix-resource-203-f9fc5a0-v1/output/epoch-203-prefix.jet";
// Recompute the real century floor and all older growth at admission. This
// thirteen-sample baseline and restore-only experiment are rejection minima,
// not a smaller full cold-epoch peak or authority to launch another replay.
const MINIMUM_FLOOR: u64 = 248_289_182_611;
const MINIMUM_PEAK: u64 = 128 << 30;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    inputs: Bound,
    admission_receipt: Bound,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Inputs {
    schema: String,
    probe_sha256: String,
    producer_unit: String,
    worker: PathBuf,
    ledger_directory: PathBuf,
    snapshot: PathBuf,
    prefix_manifest: Bound,
    prefix_validation: Bound,
    scratch_directory: PathBuf,
    output: PathBuf,
    protected_free_bytes: u64,
    candidate_incremental_peak_bytes: u64,
    minimum_free_bytes: u64,
}
fn input_policy(p: &Inputs, self_sha: &str) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-epoch203-native-input-policy-v1"
            && p.probe_sha256 == self_sha
            && p.producer_unit.starts_with("horizon-native-203-")
            && p.producer_unit.ends_with(".service")
            && p.producer_unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "wrong203 input scope or probe identity"
    );
    ensure!(
        p.protected_free_bytes >= MINIMUM_FLOOR
            && p.candidate_incremental_peak_bytes >= MINIMUM_PEAK
            && p.protected_free_bytes
                .checked_add(p.candidate_incremental_peak_bytes)
                .is_some_and(|n| p.minimum_free_bytes >= n),
        "203 complete protected restore peak is not covered"
    );
    let base = Path::new("/home/ubuntu/.jetstreamer-private");
    let run = p
        .scratch_directory
        .parent()
        .context("missing scratch parent")?;
    ensure!(
        run.parent() == Some(base)
            && run.file_name().and_then(|n| n.to_str()).is_some_and(|n| n
                .strip_prefix("epoch203-native-")
                .is_some_and(|s| !s.is_empty()))
            && p.scratch_directory == run.join("scratch")
            && p.output == run.join("native.json"),
        "203 run paths must be isolated/private/exact"
    );
    for path in [
        &p.worker,
        &p.ledger_directory,
        &p.snapshot,
        &p.prefix_manifest.path,
        &p.prefix_validation.path,
    ] {
        ensure!(
            path.is_absolute() && !path.starts_with(run),
            "retained input overlaps native output"
        );
    }
    ensure!(
        p.snapshot.file_name().and_then(|s| s.to_str()) == Some(SNAPSHOT_NAME),
        "wrong203 snapshot filename"
    );
    Ok(())
}
fn expectation(m: &HistoricalSegmentManifest, pass: &Value) -> Result<()> {
    m.validate()?;
    ensure!(
        m.epoch == 203
            && m.output_slot_start == START
            && m.output_slot_count == SLOT - START + 1
            && m.bootstrap.slot == 87_695_515
            && m.terminal.slot == SLOT
            && m.bootstrap.accounts_hash == "CYEr1vEwJyh2d4SSmnmYPYYj6EPhrDWTAJJCuzF2VhLX"
            && m.bootstrap_archive_sha256.is_none()
            && m.runtime.generation_profile == "jetstreamer-node/historical-replay-v1"
            && m.runtime.runtime_profile == "solana-v1.6.16"
            && m.runtime.runtime_revision == "86c26f843276581509c3434acc2efbf4202c44e0"
            && m.runtime.runtime_admission == SegmentRuntimeAdmission::Candidate
            && m.runtime.genesis_hash == jetstreamer_historical_protocol::MAINNET_GENESIS_HASH
            && m.worker_executable_sha256 == digest(WORKER)?
            && m.terminal.accounts_hash == ROOT_HASH,
        "not the exact203 capped-shrink canonical-root prefix"
    );
    ensure!(
        pass["schema"] == "jetstreamer-focused-qualification-artifact-validation-v1"
            && pass["validation"] == "pass"
            && pass["epoch"] == 203
            && pass["archive"] == PREFIX
            && pass["manifest"] == format!("{PREFIX}.segment.json")
            && pass["archive_sha256"] == sha256_hex_string(&m.archive_sha256)
            && pass["manifest_content_encoding"] == SEGMENT_MANIFEST_CONTENT_ENCODING
            && pass["manifest_content_sha256"] == sha256_hex_string(&m.content_sha256()?)
            && pass["output_slot_start"] == START
            && pass["output_slot_count"] == SLOT - START + 1
            && pass["bootstrap_slot"] == 87_695_515
            && pass["terminal_slot"] == SLOT
            && pass["worker_executable_sha256"] == WORKER
            && pass["runtime_profile"] == m.runtime.runtime_profile
            && pass["runtime_revision"] == m.runtime.runtime_revision
            && pass["runtime_admission"] == "candidate"
            && pass["canonical_checksum_sidecar_absent"] == true,
        "203 reader receipt does not bind the entire verified manifest"
    );
    Ok(())
}
fn admission(v: &Value, plan: &Plan, p: &Inputs, self_sha: &str, now: u64) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-epoch203-native-admission-receipt-v1"
            && v["admitted"] == true
            && v["restore_only"] == true
            && v["input_policy_sha256"] == plan.inputs.sha256
            && v["probe_sha256"] == self_sha
            && v["worker_sha256"] == WORKER
            && v["prefix_validation_sha256"] == p.prefix_validation.sha256
            && v["producer_unit"] == p.producer_unit
            && v["protected_existing_floor_bytes"] == p.protected_free_bytes
            && v["candidate_incremental_peak_bytes"] == p.candidate_incremental_peak_bytes
            && v["observed_available_bytes"]
                .as_u64()
                .is_some_and(|n| n >= p.minimum_free_bytes)
            && v["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|n| n <= now && now - n <= 900),
        "no fresh exact203 native-only protected admission"
    );
    for flag in [
        "replay_launch_authorized",
        "assembly_authorized",
        "publication_authorized",
        "local_retirement_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(v[flag] == false, "203 native admission cannot grant {flag}");
    }
    Ok(())
}
fn live_unit(p: &Inputs, iid: &str) -> Result<()> {
    ensure!(
        iid.len() == 32
            && iid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid203 invocation ID"
    );
    let result = Command::new("/usr/bin/systemctl")
        .args([
            "show",
            &p.producer_unit,
            "--property=LoadState,ActiveState,SubState,InvocationID,NRestarts,MainPID",
        ])
        .output()?;
    ensure!(result.status.success(), "cannot observe203 native unit");
    let text = String::from_utf8(result.stdout)?;
    let fields: std::collections::BTreeMap<_, _> =
        text.lines().filter_map(|s| s.split_once('=')).collect();
    for (name, expected) in [
        ("LoadState", "loaded"),
        ("ActiveState", "active"),
        ("SubState", "running"),
        ("InvocationID", iid),
        ("NRestarts", "0"),
    ] {
        ensure!(
            fields.get(name) == Some(&expected),
            "203 native unit changed:{name}"
        );
    }
    ensure!(
        fields.get("MainPID").and_then(|s| s.parse::<u32>().ok()) == Some(std::process::id()),
        "203 probe is not the exact persistent main process"
    );
    Ok(())
}
fn source_checks(p: &Inputs) -> Result<HistoricalSegmentManifest> {
    let m: HistoricalSegmentManifest = serde_json::from_slice(&bound_bytes(
        &p.prefix_manifest.path,
        &p.prefix_manifest.sha256,
        1 << 20,
    )?)?;
    let pass: Value = serde_json::from_slice(&bound_bytes(
        &p.prefix_validation.path,
        &p.prefix_validation.sha256,
        1 << 20,
    )?)?;
    expectation(&m, &pass)?;
    let lm = fs::symlink_metadata(&p.ledger_directory)?;
    ensure!(
        p.ledger_directory.canonicalize()? == p.ledger_directory
            && lm.is_dir()
            && lm.uid() == 0
            && lm.mode() & 0o222 == 0
            && fs::symlink_metadata(p.ledger_directory.join("genesis.bin"))
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "unsealed203 ledger or shadow genesis"
    );
    let sm = fs::symlink_metadata(&p.snapshot)?;
    ensure!(
        p.snapshot.canonicalize()? == p.snapshot
            && sm.is_file()
            && sm.nlink() == 1
            && sm.uid() == 0
            && sm.mode() & 0o222 == 0
            && sm.len() == SNAPSHOT_SIZE,
        "wrong immutable203 snapshot identity"
    );
    bound_bytes(&p.worker, WORKER, 256 << 20)?;
    bound_bytes(
        &p.ledger_directory.join("genesis.tar.bz2"),
        GENESIS,
        10 << 20,
    )?;
    Ok(m)
}
fn acquire_lease(path: &Path) -> Result<File> {
    private_directory(path.parent().context("missing lease parent")?)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let m = file.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == unsafe { libc::geteuid() }
            && m.nlink() == 1
            && m.mode() & 0o7777 == 0o600,
        "unsafe203 native lease"
    );
    ensure!(
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "another203 native restore owns the lease"
    );
    Ok(file)
}
fn elapsed_millis(start: Instant) -> Result<u64> {
    start
        .elapsed()
        .as_millis()
        .try_into()
        .context("203 timing overflow")
}
fn scratch_census(root: &Path) -> Result<Value> {
    let mut pending = vec![root.to_path_buf()];
    let (mut bytes, mut files, mut entries) = (0u64, 0u64, 0u64);
    while let Some(path) = pending.pop() {
        let m = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        entries = entries.checked_add(1).context("203 census overflow")?;
        ensure!(
            entries <= 1_000_000 && !m.file_type().is_symlink(),
            "unsafe203 scratch census"
        );
        bytes = bytes
            .checked_add(m.blocks().checked_mul(512).context("203 block overflow")?)
            .context("203 physical overflow")?;
        if m.is_dir() {
            for child in fs::read_dir(path)? {
                pending.push(child?.path());
            }
        } else {
            ensure!(m.is_file(), "special203 scratch file");
            files += 1;
        }
    }
    Ok(
        json!({"path":root,"physical_bytes":bytes,"files":files,"entries":entries,
        "captured_before_owned_worker_shutdown":true,"full_cold_epoch_peak_qualified":false}),
    )
}
fn execute(path: &Path, plan_sha: &str, self_sha: &str) -> Result<()> {
    let started = Instant::now();
    ensure!(
        unsafe { libc::geteuid() } == 1000,
        "isolated203 replay UID1000 required"
    );
    bound_bytes(&fs::read_link("/proc/self/exe")?, self_sha, 256 << 20)?;
    let plan: Plan = serde_json::from_slice(&bound_bytes(path, plan_sha, 1 << 20)?)?;
    ensure!(
        plan.schema == "jetstreamer-private-epoch203-native-restore-probe-plan-v1",
        "wrong203 plan"
    );
    let p: Inputs = serde_json::from_slice(&bound_bytes(
        &plan.inputs.path,
        &plan.inputs.sha256,
        1 << 20,
    )?)?;
    input_policy(&p, self_sha)?;
    let iid = env::var("INVOCATION_ID")?;
    live_unit(&p, &iid)?;
    for (name, expected) in [
        ("SOLANA_RAYON_THREADS", "16"),
        ("JETSTREAMER_HISTORICAL_CONTROL_TIMEOUT_SECS", "60"),
        ("JETSTREAMER_HISTORICAL_INITIALIZE_TIMEOUT_SECS", "3600"),
        ("JETSTREAMER_HISTORICAL_CHECKPOINT_TIMEOUT_SECS", "600"),
        ("JETSTREAMER_HISTORICAL_REAP_TIMEOUT_SECS", "120"),
    ] {
        ensure!(
            env::var(name).ok().as_deref() == Some(expected),
            "wrong bounded203 environment:{name}"
        );
    }
    private_directory(&p.scratch_directory)?;
    private_directory(p.output.parent().context("receipt parent")?)?;
    ensure!(
        fs::symlink_metadata(&p.output).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
            && fs::read_dir(&p.scratch_directory)?.next().is_none(),
        "203 attempt must be fresh"
    );
    let manifest = source_checks(&p)?;
    let a: Value = serde_json::from_slice(&bound_bytes(
        &plan.admission_receipt.path,
        &plan.admission_receipt.sha256,
        4 << 20,
    )?)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    admission(&a, &plan, &p, self_sha, now)?;
    let _lease = acquire_lease(Path::new(
        "/home/ubuntu/.jetstreamer-private/epoch203-native.lock",
    ))?;
    ensure!(
        fs::symlink_metadata(&p.output).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
            && fs::read_dir(&p.scratch_directory)?.next().is_none(),
        "203 attempt changed before lease"
    );
    let device = fs::metadata("/home/ubuntu")?.dev();
    ensure!(
        fs::metadata(&p.scratch_directory)?.dev() == device
            && fs::metadata(p.output.parent().unwrap())?.dev() == device,
        "203 attempt on wrong filesystem"
    );
    let (before, inodes) = available(&p.scratch_directory)?;
    ensure!(
        before >= p.minimum_free_bytes && inodes >= 1_000_000,
        "203 restore peak/inodes do not fit"
    );
    ensure!(
        fs::read_to_string("/proc/sys/vm/max_map_count")?
            .trim()
            .parse::<u64>()?
            >= 4_194_304,
        "203 VMA ceiling too low"
    );
    live_unit(&p, &iid)?;
    // Only initialize/freeze/shutdown. This binary never invokes a replay-entry API.
    let outcome = (|| -> Result<Value> {
        let initialize_started = Instant::now();
        let mut client = HistoricalRuntimeClient::spawn(
            SOLANA_V1_6_16_CANDIDATE,
            WorkerSpawn {
                executable: p.worker.clone(),
                initialization: HistoricalInitialization::SnapshotArchive(SnapshotInitialization {
                    ledger_path: p.ledger_directory.clone(),
                    archive_path: p.snapshot.clone(),
                    expected_slot: SLOT,
                    expected_accounts_hash: Hash::from_str(ROOT_HASH)?.to_bytes(),
                    expected_archive_sha256: Some(digest(SNAPSHOT)?),
                    expected_archive_size: Some(SNAPSHOT_SIZE),
                    scratch_parent: Some(p.scratch_directory.clone()),
                }),
            },
        )?;
        ensure!(
            client.executable_sha256() == digest(WORKER)?,
            "executed203 worker differs"
        );
        let cursor = client.initialized().next_write_version;
        let ticks = client.initialized().ticks_per_slot;
        let initialize_millis = elapsed_millis(initialize_started)?;
        let freeze_started = Instant::now();
        let actual = client.freeze_checkpoint(SLOT)?;
        let freeze_millis = elapsed_millis(freeze_started)?;
        let comparison = compare(&manifest.terminal, &actual, cursor, ticks);
        let checkpoint = json!({"slot":actual.slot,"bank_hash":Hash::new_from_array(actual.bank_hash).to_string(),
            "accounts_hash":Hash::new_from_array(actual.accounts_hash).to_string(),
            "last_blockhash":Hash::new_from_array(actual.last_blockhash).to_string(),
            "capitalization":actual.capitalization,"transaction_count":actual.transaction_count,
            "tick_height":actual.tick_height,"slot_complete":actual.slot_complete,"write_count":actual.writes.len(),
            "next_write_version":actual.next_write_version,"initialized_next_write_version":cursor,"initialized_ticks_per_slot":ticks});
        let scratch = scratch_census(&p.scratch_directory);
        let scratch_error = scratch.as_ref().err().map(|e| e.to_string());
        let shutdown_started = Instant::now();
        let shutdown = client.shutdown();
        let shutdown_millis = elapsed_millis(shutdown_started)?;
        Ok(
            json!({"native_checkpoint":checkpoint,"comparison_passed":comparison.is_ok(),
            "comparison_error":comparison.err().map(|e| e.to_string()),"shutdown_passed":shutdown.is_ok(),
            "shutdown_error":shutdown.err().map(|e| e.to_string()),"replay_entries_sent":0,
            "initialize_millis":initialize_millis,"freeze_millis":freeze_millis,"shutdown_millis":shutdown_millis,
            "scratch_before_shutdown":scratch.ok(),"scratch_measurement_error":scratch_error}),
        )
    })();
    let after = available(&p.scratch_directory)?.0;
    live_unit(&p, &iid)?;
    ensure!(
        source_checks(&p)? == manifest,
        "203 source evidence changed"
    );
    let passed = outcome.as_ref().is_ok_and(|v| {
        v["comparison_passed"] == true
            && v["shutdown_passed"] == true
            && v["scratch_measurement_error"].is_null()
    }) && after >= p.protected_free_bytes;
    let error = outcome
        .as_ref()
        .err()
        .map(|e| e.to_string().chars().take(2048).collect::<String>());
    write_receipt(
        &p.output,
        &json!({"schema":"jetstreamer-private-epoch203-native-restore-probe-v1",
        "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        "elapsed_millis":elapsed_millis(started)?,
        "invocation_id":iid,"producer_unit":p.producer_unit,"plan_sha256":plan_sha,"probe_sha256":self_sha,
        "input_policy_sha256":plan.inputs.sha256,"admission_receipt_sha256":plan.admission_receipt.sha256,
        "worker_sha256":WORKER,"snapshot_sha256":SNAPSHOT,"snapshot_bytes":SNAPSHOT_SIZE,
        "prefix_manifest_sha256":p.prefix_manifest.sha256,"prefix_validation_sha256":p.prefix_validation.sha256,
        "prefix_manifest_content_sha256":sha256_hex_string(&manifest.content_sha256()?),
        "original_producer_cursor":manifest.terminal.next_write_version,"native_result":outcome.ok(),"error":error,
        "passed":passed,"available_bytes_before":before,"available_bytes_after":after,"replay_entries_sent":0,
        "prefix_archive_freshly_verified_by_this_probe":false,"executing_suffix_must_repeat_native_tuple_check":true,
        "replay_launch_authorized":false,"assembly_authorized":false,"canonical_sidecar_authorized":false,
        "publication_authorized":false,"local_retirement_authorized":false,"remote_mutations":false,"r2_mutations":false}),
    )?;
    ensure!(passed, "203 native comparison failed; outcome preserved");
    Ok(())
}
fn main() {
    let a: Vec<_> = env::args().skip(1).collect();
    let result = if a.len() == 5 && a[1] == "--plan-sha256" && a[3] == "--self-sha256" {
        execute(Path::new(&a[0]), &a[2], &a[4])
    } else {
        Err(anyhow::anyhow!(
            "usage: jetstreamer-epoch203-native-restore-probe PLAN --plan-sha256 HEX --self-sha256 HEX"
        ))
    };
    if let Err(error) = result {
        eprintln!("203 native restore failed: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn manifest() -> HistoricalSegmentManifest {
        let hash = |n| Hash::new_from_array([n; 32]).to_string();
        serde_json::from_value(json!({"schema_version":1,"epoch":203,
            "output_slot_start":START,"output_slot_count":SLOT-START+1,
            "runtime":{"generation_profile":"jetstreamer-node/historical-replay-v1",
                "runtime_profile":"solana-v1.6.16","runtime_admission":"candidate",
                "runtime_revision":"86c26f843276581509c3434acc2efbf4202c44e0",
                "runtime_toolchain":"rustc 1.51.0","runtime_target":"x86_64-unknown-linux-gnu",
                "genesis_hash":jetstreamer_historical_protocol::MAINNET_GENESIS_HASH},
            "worker_executable_sha256":WORKER,"archive_sha256":"ab".repeat(32),
            "bootstrap":{"slot":87695515,"bank_hash":hash(1),
                "accounts_hash":"CYEr1vEwJyh2d4SSmnmYPYYj6EPhrDWTAJJCuzF2VhLX",
                "last_blockhash":hash(2),"capitalization":1000,"transaction_count":10,
                "tick_height":87695515u64*64,"slot_complete":true,"write_count":0,"next_write_version":100},
            "terminal":{"slot":SLOT,"bank_hash":hash(3),"accounts_hash":ROOT_HASH,
                "last_blockhash":hash(4),"capitalization":1100,"transaction_count":20,
                "tick_height":SLOT*64,"slot_complete":true,"write_count":10,"next_write_version":200},
            "emitted_raw_write_versions":{"start":100,"end":200}})).unwrap()
    }
    fn pass(m: &HistoricalSegmentManifest) -> Value {
        json!({"schema":"jetstreamer-focused-qualification-artifact-validation-v1","validation":"pass",
            "epoch":203,"archive":PREFIX,"manifest":format!("{PREFIX}.segment.json"),
            "archive_sha256":sha256_hex_string(&m.archive_sha256),
            "manifest_content_encoding":SEGMENT_MANIFEST_CONTENT_ENCODING,
            "manifest_content_sha256":sha256_hex_string(&m.content_sha256().unwrap()),
            "output_slot_start":START,"output_slot_count":SLOT-START+1,"bootstrap_slot":87695515,
            "terminal_slot":SLOT,"worker_executable_sha256":WORKER,
            "runtime_profile":"solana-v1.6.16","runtime_revision":"86c26f843276581509c3434acc2efbf4202c44e0",
            "runtime_admission":"candidate","canonical_checksum_sidecar_absent":true})
    }
    fn inputs() -> Inputs {
        Inputs {
            schema: "jetstreamer-epoch203-native-input-policy-v1".into(),
            probe_sha256: "a".repeat(64),
            producer_unit: "horizon-native-203-test.service".into(),
            worker: "/sealed/worker".into(),
            ledger_directory: "/sealed/ledger".into(),
            snapshot: Path::new("/sealed").join(SNAPSHOT_NAME),
            prefix_manifest: Bound {
                path: "/sealed/manifest".into(),
                sha256: "b".repeat(64),
            },
            prefix_validation: Bound {
                path: "/sealed/validation".into(),
                sha256: "c".repeat(64),
            },
            scratch_directory: "/home/ubuntu/.jetstreamer-private/epoch203-native-test/scratch"
                .into(),
            output: "/home/ubuntu/.jetstreamer-private/epoch203-native-test/native.json".into(),
            protected_free_bytes: MINIMUM_FLOOR,
            candidate_incremental_peak_bytes: MINIMUM_PEAK,
            minimum_free_bytes: MINIMUM_FLOOR + MINIMUM_PEAK,
        }
    }
    #[test]
    fn exact203_prefix_binds_complete_independent_reader_content() {
        let m = manifest();
        let p = pass(&m);
        expectation(&m, &p).unwrap();
        // A prior receipt binding only the archive/range is insufficient.
        for key in [
            "manifest_content_sha256",
            "manifest_content_encoding",
            "validation",
            "worker_executable_sha256",
            "canonical_checksum_sidecar_absent",
        ] {
            let mut bad = p.clone();
            bad.as_object_mut().unwrap().remove(key);
            assert!(expectation(&m, &bad).is_err(), "{key}");
        }
        for (key, value) in [
            ("archive", json!("/other/epoch-203-prefix.jet")),
            ("manifest", json!("/other/manifest")),
            ("archive_sha256", json!("de".repeat(32))),
            ("manifest_content_sha256", json!("de".repeat(32))),
            ("epoch", json!(213)),
            ("terminal_slot", json!(SLOT + 1)),
            ("runtime_admission", json!("verified")),
            ("canonical_checksum_sidecar_absent", json!(false)),
        ] {
            let mut bad = p.clone();
            bad[key] = value;
            assert!(expectation(&m, &bad).is_err(), "{key}");
        }
    }
    #[test]
    fn checkpoint_mutations_cannot_reuse_a_range_only_reader_receipt() {
        let m = manifest();
        let p = pass(&m);
        let changes: [fn(&mut HistoricalSegmentManifest); 18] = [
            |m| m.epoch = 213,
            |m| m.output_slot_start += 1,
            |m| m.output_slot_count -= 1,
            |m| m.bootstrap.slot -= 1,
            |m| m.terminal.slot -= 1,
            |m| m.terminal.bank_hash = Hash::new_from_array([9; 32]).to_string(),
            |m| m.terminal.accounts_hash = Hash::new_from_array([9; 32]).to_string(),
            |m| m.terminal.last_blockhash = Hash::new_from_array([9; 32]).to_string(),
            |m| m.terminal.capitalization += 1,
            |m| m.terminal.transaction_count += 1,
            |m| m.terminal.tick_height += 1,
            |m| m.terminal.slot_complete = false,
            |m| m.terminal.write_count += 1,
            |m| {
                m.terminal.next_write_version += 1;
                m.emitted_raw_write_versions.end += 1
            },
            |m| m.worker_executable_sha256 = [9; 32],
            |m| m.runtime.runtime_revision = "other".into(),
            |m| m.runtime.genesis_hash = Hash::new_from_array([9; 32]).to_string(),
            |m| m.bootstrap_archive_sha256 = Some([9; 32]),
        ];
        for change in changes {
            let mut bad = m.clone();
            change(&mut bad);
            assert!(expectation(&bad, &p).is_err());
        }
    }
    #[test]
    fn input_scope_and_complete_resource_minima_are_fail_closed() {
        input_policy(&inputs(), &"a".repeat(64)).unwrap();
        let changes: [fn(&mut Inputs); 10] = [
            |p| p.probe_sha256 = "b".repeat(64),
            |p| p.producer_unit = "horizon-native-213-test.service".into(),
            |p| p.scratch_directory = "/home/ubuntu/horizon/scratch".into(),
            |p| p.output = p.scratch_directory.join("native.json"),
            |p| p.snapshot = "/sealed/wrong.tar.zst".into(),
            |p| p.prefix_manifest.path = p.output.clone(),
            |p| p.protected_free_bytes = MINIMUM_FLOOR - 1,
            |p| p.candidate_incremental_peak_bytes = MINIMUM_PEAK - 1,
            |p| p.minimum_free_bytes -= 1,
            |p| p.protected_free_bytes = u64::MAX,
        ];
        for change in changes {
            let mut p = inputs();
            change(&mut p);
            assert!(input_policy(&p, &"a".repeat(64)).is_err());
        }
    }
    #[test]
    fn admission_binds_exact_policy_reader_peak_clock_and_no_extra_authority() {
        let p = inputs();
        let plan = Plan {
            schema: "test".into(),
            inputs: Bound {
                path: "/sealed/inputs".into(),
                sha256: "d".repeat(64),
            },
            admission_receipt: Bound {
                path: "/sealed/admission".into(),
                sha256: "e".repeat(64),
            },
        };
        let v = json!({"schema":"jetstreamer-epoch203-native-admission-receipt-v1","admitted":true,"restore_only":true,
            "input_policy_sha256":plan.inputs.sha256,"probe_sha256":p.probe_sha256,"worker_sha256":WORKER,
            "prefix_validation_sha256":p.prefix_validation.sha256,"producer_unit":p.producer_unit,
            "protected_existing_floor_bytes":p.protected_free_bytes,"candidate_incremental_peak_bytes":MINIMUM_PEAK,
            "observed_available_bytes":p.minimum_free_bytes,"recorded_unix_seconds":1000,
            "replay_launch_authorized":false,"assembly_authorized":false,"publication_authorized":false,
            "local_retirement_authorized":false,"remote_mutations":false,"r2_mutations":false});
        admission(&v, &plan, &p, &p.probe_sha256, 1100).unwrap();
        for (key, value) in [
            ("input_policy_sha256", json!("f".repeat(64))),
            ("prefix_validation_sha256", json!("f".repeat(64))),
            ("probe_sha256", json!("f".repeat(64))),
            ("worker_sha256", json!("f".repeat(64))),
            ("producer_unit", json!("horizon-native-203-other.service")),
            (
                "protected_existing_floor_bytes",
                json!(p.protected_free_bytes - 1),
            ),
            ("candidate_incremental_peak_bytes", json!(MINIMUM_PEAK - 1)),
            ("observed_available_bytes", json!(p.minimum_free_bytes - 1)),
            ("recorded_unix_seconds", json!(1101)),
            ("recorded_unix_seconds", json!(199)),
            ("restore_only", json!(false)),
        ] {
            let mut bad = v.clone();
            bad[key] = value;
            assert!(
                admission(&bad, &plan, &p, &p.probe_sha256, 1100).is_err(),
                "{key}"
            );
        }
        for key in [
            "replay_launch_authorized",
            "assembly_authorized",
            "publication_authorized",
            "local_retirement_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            let mut bad = v.clone();
            bad[key] = json!(true);
            assert!(
                admission(&bad, &plan, &p, &p.probe_sha256, 1100).is_err(),
                "{key}"
            );
            bad.as_object_mut().unwrap().remove(key);
            assert!(
                admission(&bad, &plan, &p, &p.probe_sha256, 1100).is_err(),
                "{key}"
            );
        }
    }
    #[test]
    fn schemas_never_accept_a_replay_or_mutation_switch() {
        let mut plan = json!({"schema":"test","inputs":{"path":"/sealed/inputs","sha256":"a".repeat(64)},
            "admission_receipt":{"path":"/sealed/admission","sha256":"b".repeat(64)}});
        assert!(serde_json::from_value::<Plan>(plan.clone()).is_ok());
        plan["allow_replay"] = json!(true);
        assert!(
            serde_json::from_value::<Plan>(plan)
                .unwrap_err()
                .to_string()
                .contains("unknown field")
        );
        let mut p = serde_json::to_value(inputs()).unwrap();
        assert!(serde_json::from_value::<Inputs>(p.clone()).is_ok());
        p["allow_replay"] = json!(true);
        assert!(
            serde_json::from_value::<Inputs>(p)
                .unwrap_err()
                .to_string()
                .contains("unknown field")
        );
    }
    #[test]
    fn native_lease_is_exclusive_and_rejects_link_or_permission_substitution() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("native.lock");
        let first = acquire_lease(&path).unwrap();
        assert!(acquire_lease(&path).is_err());
        drop(first);
        drop(acquire_lease(&path).unwrap());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(acquire_lease(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let link = temp.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(acquire_lease(&link).is_err());
        fs::hard_link(&path, temp.path().join("hardlink")).unwrap();
        assert!(acquire_lease(&path).is_err());
    }
    #[test]
    fn scratch_measurement_is_bounded_private_and_never_a_full_epoch_peak() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let file = temp.path().join("state");
        fs::write(&file, b"state").unwrap();
        let result = scratch_census(temp.path()).unwrap();
        assert_eq!(result["files"], 1);
        assert_eq!(result["captured_before_owned_worker_shutdown"], true);
        assert_eq!(result["full_cold_epoch_peak_qualified"], false);
        symlink(&file, temp.path().join("link")).unwrap();
        assert!(scratch_census(temp.path()).is_err());
    }
}
