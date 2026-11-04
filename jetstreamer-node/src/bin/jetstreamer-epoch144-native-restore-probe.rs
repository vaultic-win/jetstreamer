//! Exact 62639490 native comparison only. Never a suffix or publication path.
//! Reuse the unchanged 140 comparison/client/immutable-I/O helpers, not its plan.
#[allow(dead_code)]
#[path = "jetstreamer-epoch140-native-restore-probe.rs"]
mod baseline;
use {
    anyhow::{Context, Result, ensure},
    baseline::historical::{
        HistoricalInitialization, HistoricalRuntimeClient, SOLANA_V1_4_25_CANDIDATE,
        SnapshotInitialization, WorkerSpawn,
    },
    baseline::{available, bound_bytes, compare, digest, private_directory, write_receipt},
    jetstreamer_node::segment_manifest::SegmentCheckpointSummary,
    serde::{Deserialize, Serialize},
    serde_json::{Value, json},
    solana_hash::Hash,
    std::{
        env, fs,
        os::unix::fs::MetadataExt,
        path::{Path, PathBuf},
        str::FromStr,
        time::{SystemTime, UNIX_EPOCH},
    },
};
const SLOT: u64 = 62_639_490;
const PROTECTED: u64 = 4_740_696_923_590;
const PEAK: u64 = 40 << 30;
const WORKER: &str = "2cca500106d274ebfbbc8c5bfa0e6e8343cd5e41003f9e82c93282800732d8c8";
const SNAPSHOT: &str = "f170976b2bc3f2d55dd0fbb5a415bfeae8d0903a0ad69334d8aa993b5cab35ae";
const SNAPSHOT_NAME: &str =
    "snapshot-62639490-59bAQjc2c1VqNWqGoCacp3tnyNyie3EYx4bjttvJhgeT.tar.zst";
const MANIFEST: &str = "691d5f3768b8c283678937b49790606b6091d4ab632372bfff38664c005b544a";
const PREFIX_PASS: &str = "35b52ea28979dc8bc360afde41b1b71059a8451c801b71e65ebeac458c59f044";
const CLOCK: &str = "ea9c16d375feac1a1ec0ed7304f7711e195ed0b0bd4f3ae4b1d6a100bfd11f11";
const GENESIS: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
const ARCHIVE: &str = "917f700274c0ff0386cd8be2f27eb2ace9f3bc7dff38e1010d0c04bb79b8c273";
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    inputs: Bound,
    admission_receipt: Bound,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Inputs {
    schema: String,
    probe_sha256: String,
    worker: PathBuf,
    ledger_directory: PathBuf,
    prefix_manifest: Bound,
    prefix_validation: Bound,
    serialized_clock: Bound,
    scratch_directory: PathBuf,
    output: PathBuf,
    minimum_free_bytes: u64,
}
fn validate_admission(value: &Value, inputs: &Bound, self_sha: &str, now: u64) -> Result<()> {
    ensure!(
        value["schema"] == "jetstreamer-epoch144-native-admission-receipt-v2"
            && value["admitted"] == true
            && value["restore_only"] == true
            && value["replay_launch_authorized"] == false
            && value["publication_authorized"] == false
            && value["remote_mutations"] == false
            && value["r2_mutations"] == false
            && value["input_policy_sha256"] == inputs.sha256
            && value["probe_sha256"] == self_sha
            && value["worker_sha256"] == WORKER
            && value["protected_existing_floor_bytes"] == PROTECTED
            && value["candidate_incremental_peak_bytes"]
                .as_u64()
                .is_some_and(|n| n >= PEAK)
            && value["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|n| n <= now && now - n <= 900),
        "no fresh exact 144 native-only admission"
    );
    Ok(())
}
fn read(bound: &Bound, expected: &str) -> Result<Value> {
    ensure!(bound.sha256 == expected, "wrong 144 bound evidence digest");
    Ok(serde_json::from_slice(&bound_bytes(
        &bound.path,
        expected,
        65536,
    )?)?)
}
fn scratch_census(root: &Path) -> Result<Value> {
    let mut pending = vec![root.to_path_buf()];
    let (mut physical, mut apparent, mut files, mut entries) = (0u64, 0u64, 0u64, 0u64);
    while let Some(path) = pending.pop() {
        let m = fs::symlink_metadata(&path)?;
        entries = entries.checked_add(1).context("census count overflow")?;
        ensure!(
            entries <= 1_000_000 && !m.file_type().is_symlink(),
            "unsafe or oversized 144 scratch census"
        );
        physical = physical
            .checked_add(m.blocks().checked_mul(512).context("block overflow")?)
            .context("physical overflow")?;
        if m.is_dir() {
            for child in fs::read_dir(&path)? {
                pending.push(child?.path());
            }
        } else {
            ensure!(m.is_file(), "special file in 144 scratch");
            files += 1;
            apparent = apparent.checked_add(m.len()).context("apparent overflow")?;
        }
    }
    Ok(
        json!({"path":root,"physical_bytes":physical,"apparent_bytes":apparent,"files":files,"entries":entries,
        "captured_before_owned_worker_shutdown":true,"not_a_full_cold_epoch_resource_bound":true}),
    )
}
fn expectation(manifest: &Value, pass: &Value, clock: &Value) -> Result<SegmentCheckpointSummary> {
    ensure!(
        manifest["epoch"] == 144
            && manifest["schema_version"] == 1
            && manifest["output_slot_start"] == 62208000
            && manifest["output_slot_count"] == 431491
            && manifest["archive_sha256"] == ARCHIVE
            && manifest["worker_executable_sha256"] == WORKER
            && manifest["runtime"]["runtime_profile"] == "solana-v1.4.25"
            && pass["schema"] == "jetstreamer-focused-qualification-artifact-validation-v1"
            && pass["validation"] == "pass"
            && pass["epoch"] == 144
            && pass["archive_sha256"] == ARCHIVE
            && pass["worker_executable_sha256"] == WORKER
            && pass["terminal_slot"] == SLOT
            && pass["output_slot_start"] == 62208000
            && pass["output_slot_count"] == 431491
            && pass["canonical_checksum_sidecar_absent"] == true,
        "wrong independently verified 144 prefix"
    );
    ensure!(
        clock["schema"] == "jetstreamer-epoch144-serialized-snapshot-clock-v1"
            && clock["input_sha256"] == SNAPSHOT
            && clock["pinned_typed_serialized_clock_only"] == true
            && clock["native_bank_restored"] == false
            && clock["replay_launch_authorized"] == false
            && clock["publication_authorized"] == false
            && clock["census"]["clock"]["ticks_per_slot"] == 64
            && clock["census"]["clock"]["hashes_per_tick"] == 12500,
        "wrong 144 serialized source"
    );
    let expected: SegmentCheckpointSummary = serde_json::from_value(manifest["terminal"].clone())?;
    ensure!(
        expected.slot == SLOT
            && expected.slot_complete
            && expected.accounts_hash == "59bAQjc2c1VqNWqGoCacp3tnyNyie3EYx4bjttvJhgeT",
        "wrong 144 root"
    );
    for (a, b) in [
        ("slot", "slot"),
        ("bank_hash", "bank_hash"),
        ("last_blockhash", "last_blockhash"),
        ("capitalization", "capitalization"),
        ("transaction_count", "transaction_count"),
        ("tick_height", "tick_height"),
        ("slot_complete", "complete"),
    ] {
        ensure!(
            manifest["terminal"][a] == clock["census"]["clock"][b],
            "serialized 144 terminal mismatch:{a}"
        );
    }
    Ok(expected)
}
fn source_checks(plan: &Inputs, self_sha: &str) -> Result<(SegmentCheckpointSummary, PathBuf)> {
    ensure!(
        plan.schema == "jetstreamer-epoch144-native-input-policy-v1"
            && plan.probe_sha256 == self_sha
            && plan.minimum_free_bytes >= PROTECTED + PEAK,
        "wrong 144 input policy"
    );
    let lm = fs::symlink_metadata(&plan.ledger_directory)?;
    ensure!(
        plan.ledger_directory.canonicalize()? == plan.ledger_directory
            && lm.is_dir()
            && lm.uid() == 0
            && lm.mode() & 0o222 == 0
            && !plan.ledger_directory.join("genesis.bin").try_exists()?,
        "unsealed ledger/shadow genesis"
    );
    let snapshot = plan.ledger_directory.join(SNAPSHOT_NAME);
    let sm = fs::symlink_metadata(&snapshot)?;
    ensure!(
        sm.is_file()
            && sm.uid() == 0
            && sm.mode() & 0o222 == 0
            && sm.nlink() == 1
            && sm.len() == 2569233422,
        "wrong immutable 144 compressed input"
    );
    bound_bytes(&plan.worker, WORKER, 256 << 20)?;
    bound_bytes(
        &plan.ledger_directory.join("genesis.tar.bz2"),
        GENESIS,
        10 << 20,
    )?;
    let manifest = read(&plan.prefix_manifest, MANIFEST)?;
    let pass = read(&plan.prefix_validation, PREFIX_PASS)?;
    let clock = read(&plan.serialized_clock, CLOCK)?;
    Ok((expectation(&manifest, &pass, &clock)?, snapshot))
}
fn check_inputs(path: &Path, policy_sha: &str, self_sha: &str, receipt: &Path) -> Result<()> {
    use {
        jetstreamer_node::archive_checksum::{
            archive_file_identity, open_regular_nofollow, path_matches_archive_identity,
        },
        sha2::{Digest, Sha256},
        std::{io::Read, time::Instant},
    };
    ensure!(
        unsafe { libc::geteuid() } == 1001,
        "isolated input-reader UID 1001 required"
    );
    bound_bytes(&fs::read_link("/proc/self/exe")?, self_sha, 256 << 20)?;
    let plan: Inputs = serde_json::from_slice(&bound_bytes(path, policy_sha, 1 << 20)?)?;
    let (expected, snapshot) = source_checks(&plan, self_sha)?;
    let start = Instant::now();
    let mut file = open_regular_nofollow(&snapshot)?;
    let identity = archive_file_identity(&file)?;
    let mut hash = Sha256::new();
    let mut bytes = 0u64;
    let mut buf = vec![0u8; 1 << 20];
    loop {
        ensure!(
            start.elapsed().as_secs() < 120
                && available(Path::new("/home/sol"))?.0 >= PROTECTED + (1 << 20),
            "input probe resource guard failed"
        );
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
        bytes += n as u64;
    }
    ensure!(
        bytes == 2569233422
            && format!("{:x}", hash.finalize()) == SNAPSHOT
            && archive_file_identity(&file)? == identity
            && path_matches_archive_identity(&snapshot, identity)?,
        "input hash/identity changed"
    );
    let iid = env::var("INVOCATION_ID")?;
    ensure!(
        iid.len() == 32
            && iid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid capability invocation"
    );
    write_receipt(
        receipt,
        &json!({"schema":"jetstreamer-epoch144-native-input-capability-v1","invocation_id":iid,
        "input_policy_sha256":policy_sha,"probe_sha256":self_sha,"worker_sha256":WORKER,"snapshot_sha256":SNAPSHOT,
        "snapshot_device":file.metadata()?.dev(),"snapshot_inode":file.metadata()?.ino(),"snapshot_bytes":bytes,
        "source_expected_terminal":expected,"private_source_permissions_changed":false,"snapshot_copied":false,
        "native_bank_restored":false,"worker_spawned":false,"native_restore_authorized":false,
        "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false}),
    )?;
    Ok(())
}
fn execute(path: &Path, plan_sha: &str, self_sha: &str) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 1001,
        "isolated replay UID 1001 required"
    );
    let self_path = fs::read_link("/proc/self/exe")?;
    bound_bytes(&self_path, self_sha, 256 << 20)?;
    let binding: Plan = serde_json::from_slice(&bound_bytes(path, plan_sha, 1 << 20)?)?;
    ensure!(
        binding.schema == "jetstreamer-private-epoch144-native-restore-probe-plan-v2",
        "wrong 144 plan schema"
    );
    let plan: Inputs = serde_json::from_slice(&bound_bytes(
        &binding.inputs.path,
        &binding.inputs.sha256,
        1 << 20,
    )?)?;
    ensure!(
        plan.schema == "jetstreamer-epoch144-native-input-policy-v1"
            && plan.probe_sha256 == self_sha
            && plan.minimum_free_bytes >= PROTECTED + PEAK,
        "wrong 144 native scope/complete peak"
    );
    let iid = env::var("INVOCATION_ID")?;
    ensure!(
        iid.len() == 32
            && iid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid invocation"
    );
    for (key, value) in [
        ("SOLANA_RAYON_THREADS", "2"),
        ("JETSTREAMER_HISTORICAL_CONTROL_TIMEOUT_SECS", "60"),
        ("JETSTREAMER_HISTORICAL_INITIALIZE_TIMEOUT_SECS", "900"),
        ("JETSTREAMER_HISTORICAL_CHECKPOINT_TIMEOUT_SECS", "600"),
        ("JETSTREAMER_HISTORICAL_REAP_TIMEOUT_SECS", "120"),
    ] {
        ensure!(
            env::var(key).ok().as_deref() == Some(value),
            "wrong bounded environment:{key}"
        );
    }
    private_directory(&plan.scratch_directory)?;
    private_directory(plan.output.parent().context("output parent")?)?;
    ensure!(
        plan.output.is_absolute()
            && !plan.output.starts_with(&plan.scratch_directory)
            && !plan.output.try_exists()?
            && fs::symlink_metadata(&plan.output).is_err()
            && fs::read_dir(&plan.scratch_directory)?.next().is_none(),
        "attempt is not fresh/disjoint"
    );
    let (expected, snapshot) = source_checks(&plan, self_sha)?;
    let admission: Value = serde_json::from_slice(&bound_bytes(
        &binding.admission_receipt.path,
        &binding.admission_receipt.sha256,
        4 << 20,
    )?)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    validate_admission(&admission, &binding.inputs, self_sha, now)?;
    let device = fs::metadata("/home/sol")?.dev();
    ensure!(
        fs::metadata(&plan.scratch_directory)?.dev() == device
            && fs::metadata(plan.output.parent().unwrap())?.dev() == device,
        "scratch/receipt filesystem differs"
    );
    let (free, inodes) = available(&plan.scratch_directory)?;
    ensure!(
        free >= plan.minimum_free_bytes && inodes >= 1_000_000,
        "native peak/inodes do not fit"
    );
    ensure!(
        fs::read_to_string("/proc/sys/vm/max_map_count")?
            .trim()
            .parse::<u64>()?
            >= 4_194_304,
        "host VMA ceiling too low"
    );
    // Only initialization, freeze and shutdown APIs; no replay entry API exists in this tool.
    let outcome = (|| -> Result<Value> {
        let mut client = HistoricalRuntimeClient::spawn(
            SOLANA_V1_4_25_CANDIDATE,
            WorkerSpawn {
                executable: plan.worker.clone(),
                initialization: HistoricalInitialization::SnapshotArchive(SnapshotInitialization {
                    ledger_path: plan.ledger_directory.clone(),
                    archive_path: snapshot,
                    expected_slot: SLOT,
                    expected_accounts_hash: Hash::from_str(&expected.accounts_hash)?.to_bytes(),
                    expected_archive_sha256: Some(digest(SNAPSHOT)?),
                    expected_archive_size: Some(2569233422),
                    scratch_parent: Some(plan.scratch_directory.clone()),
                }),
            },
        )?;
        ensure!(
            client.executable_sha256() == digest(WORKER)?,
            "executed worker differs"
        );
        let cursor = client.initialized().next_write_version;
        let ticks = client.initialized().ticks_per_slot;
        let actual = client.freeze_checkpoint(SLOT)?;
        let comparison = compare(&expected, &actual, cursor, ticks);
        let checkpoint = json!({"slot":actual.slot,"bank_hash":Hash::new_from_array(actual.bank_hash).to_string(),
            "accounts_hash":Hash::new_from_array(actual.accounts_hash).to_string(),"last_blockhash":Hash::new_from_array(actual.last_blockhash).to_string(),
            "capitalization":actual.capitalization,"transaction_count":actual.transaction_count,"tick_height":actual.tick_height,
            "slot_complete":actual.slot_complete,"write_count":actual.writes.len(),"next_write_version":actual.next_write_version,
            "initialized_next_write_version":cursor,"initialized_ticks_per_slot":ticks});
        // The client's temporary account state disappears on shutdown.
        let scratch = scratch_census(&plan.scratch_directory);
        let scratch_error = scratch.as_ref().err().map(|e| e.to_string());
        let shutdown = client.shutdown();
        Ok(
            json!({"native_checkpoint":checkpoint,"comparison_passed":comparison.is_ok(),"comparison_error":comparison.err().map(|e|e.to_string()),
            "shutdown_passed":shutdown.is_ok(),"shutdown_error":shutdown.err().map(|e|e.to_string()),"replay_entries_sent":0,
            "scratch_before_shutdown":scratch.ok(),"scratch_measurement_error":scratch_error}),
        )
    })();
    let passed = outcome
        .as_ref()
        .is_ok_and(|v| v["comparison_passed"] == true && v["shutdown_passed"] == true);
    let error = outcome
        .as_ref()
        .err()
        .map(|e| e.to_string().chars().take(2048).collect::<String>());
    let after = available(&plan.scratch_directory)?.0;
    for (bound, sha) in [
        (&plan.prefix_manifest, MANIFEST),
        (&plan.prefix_validation, PREFIX_PASS),
        (&plan.serialized_clock, CLOCK),
    ] {
        read(bound, sha)?;
    }
    write_receipt(
        &plan.output,
        &json!({"schema":"jetstreamer-private-epoch144-native-restore-probe-v1","invocation_id":iid,
        "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),"plan_sha256":plan_sha,"self_sha256":self_sha,
        "input_policy_sha256":binding.inputs.sha256,"admission_receipt_sha256":binding.admission_receipt.sha256,
        "worker_sha256":WORKER,"snapshot_sha256":SNAPSHOT,"prefix_manifest_sha256":MANIFEST,"prefix_validation_sha256":PREFIX_PASS,
        "serialized_clock_sha256":CLOCK,"original_producer_cursor":expected.next_write_version,"native_result":outcome.ok(),"error":error,
        "passed":passed && after>=PROTECTED,"available_bytes_before":free,"available_bytes_after":after,"replay_entries_sent":0,
        "native_consensus_comparison_only":true,"executing_suffix_must_repeat_native_tuple_check":true,
        "replay_launch_authorized":false,"assembly_authorized":false,"publication_authorized":false,
        "local_retirement_authorized":false,"remote_mutations":false,"r2_mutations":false}),
    )?;
    ensure!(
        passed && after >= PROTECTED,
        "native 144 comparison failed; outcome preserved"
    );
    Ok(())
}
fn main() {
    let a: Vec<_> = env::args().skip(1).collect();
    let result = if a.len() == 8
        && a[0] == "--check-inputs-only"
        && a[2] == "--policy-sha256"
        && a[4] == "--self-sha256"
        && a[6] == "--receipt"
    {
        check_inputs(Path::new(&a[1]), &a[3], &a[5], Path::new(&a[7]))
    } else if a.len() == 5 && a[1] == "--plan-sha256" && a[3] == "--self-sha256" {
        execute(Path::new(&a[0]), &a[2], &a[4])
    } else {
        Err(anyhow::anyhow!(
            "usage: PLAN --plan-sha256 HEX --self-sha256 HEX"
        ))
    };
    if let Err(e) = result {
        eprintln!("private144 native-only probe failed:{e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn admission_binds_prior_input_policy_without_a_hash_cycle() {
        use sha2::{Digest, Sha256};
        let inputs = Bound {
            path: "/sealed/inputs.json".into(),
            sha256: "a".repeat(64),
        };
        let tool = "b".repeat(64);
        let admission = json!({"schema":"jetstreamer-epoch144-native-admission-receipt-v2","admitted":true,"restore_only":true,
            "replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false,
            "input_policy_sha256":inputs.sha256,"probe_sha256":tool,"worker_sha256":WORKER,
            "protected_existing_floor_bytes":PROTECTED,"candidate_incremental_peak_bytes":PEAK,"recorded_unix_seconds":100});
        validate_admission(&admission, &inputs, &tool, 101).unwrap();
        let receipt_sha = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&admission).unwrap())
        );
        let final_plan = json!({"schema":"jetstreamer-private-epoch144-native-restore-probe-plan-v2","inputs":inputs,
            "admission_receipt":{"path":"/receipt/admitted.json","sha256":receipt_sha}});
        serde_json::from_value::<Plan>(final_plan).unwrap();
        // Admission is created before the final plan and does not know its hash.
        assert!(admission.get("plan_sha256").is_none());
        for (key, value) in [
            ("input_policy_sha256", json!("c".repeat(64))),
            (
                "schema",
                json!("jetstreamer-epoch144-native-admission-receipt-v1"),
            ),
            ("recorded_unix_seconds", json!(102)),
            ("replay_launch_authorized", json!(true)),
            ("candidate_incremental_peak_bytes", json!(PEAK - 1)),
        ] {
            let mut bad = admission.clone();
            bad[key] = value;
            assert!(
                validate_admission(&bad, &inputs, &tool, 101).is_err(),
                "{key}"
            );
        }
    }
    #[test]
    fn pre_shutdown_census_counts_only_regular_private_files() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("fixture"), b"123456789").unwrap();
        let value = scratch_census(root.path()).unwrap();
        assert_eq!(value["files"], 1);
        assert_eq!(value["apparent_bytes"], 9);
        std::os::unix::fs::symlink("/tmp", root.path().join("foreign-link")).unwrap();
        assert!(scratch_census(root.path()).is_err());
    }
    #[test]
    #[ignore = "root read-only exact retained 144 manifest/pass/clock qualification; no restoration"]
    fn root_actual_sources_match_the_exact144_expectation() {
        use sha2::{Digest, Sha256};
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let mut values = Vec::new();
        for (path, sha) in [
            (
                "/home/sol/.jetstreamer-private/epoch144-upgradeable-loader-focus-20261016-v1/output/epoch-144-through-62639490.jet.segment.json",
                MANIFEST,
            ),
            (
                "/var/lib/jetstreamer/horizon-epoch144-retained-prefix-audit-20261021-v1/epoch-144-prefix.validation.json",
                PREFIX_PASS,
            ),
            (
                "/var/lib/jetstreamer-horizon-epoch144-snapshot-clock-20261021-v1/clock.json",
                CLOCK,
            ),
        ] {
            let bytes = fs::read(path).unwrap();
            assert!(bytes.len() <= 65536);
            assert_eq!(format!("{:x}", Sha256::digest(&bytes)), sha);
            values.push(serde_json::from_slice::<Value>(&bytes).unwrap());
        }
        let e = expectation(&values[0], &values[1], &values[2]).unwrap();
        assert_eq!(e.capitalization, 488586979125186779u64);
        assert_eq!(e.slot, SLOT);
    }
    fn sources() -> (Value, Value, Value) {
        let terminal = json!({"slot":SLOT,"bank_hash":"CoM8739uCp31r3ZJoLKPzag2aG9JcL9naR5TMaFAZAZ9",
            "accounts_hash":"59bAQjc2c1VqNWqGoCacp3tnyNyie3EYx4bjttvJhgeT",
            "last_blockhash":"7AFqLphUQsd92pntzKB25ad5iPiJae9yjt742HFgLuoV","capitalization":488586979125186779u64,
            "transaction_count":10186599902u64,"tick_height":4008927424u64,"slot_complete":true,
            "write_count":34,"next_write_version":31367810617u64});
        let manifest = json!({"schema_version":1,"epoch":144,"output_slot_start":62208000,"output_slot_count":431491,
            "archive_sha256":ARCHIVE,"worker_executable_sha256":WORKER,"runtime":{"runtime_profile":"solana-v1.4.25"},"terminal":terminal});
        let pass = json!({"schema":"jetstreamer-focused-qualification-artifact-validation-v1","validation":"pass","epoch":144,
            "archive_sha256":ARCHIVE,"worker_executable_sha256":WORKER,"terminal_slot":SLOT,"output_slot_start":62208000,
            "output_slot_count":431491,"canonical_checksum_sidecar_absent":true});
        let mut clock_fields = terminal;
        clock_fields["complete"] = json!(true);
        clock_fields["ticks_per_slot"] = json!(64);
        clock_fields["hashes_per_tick"] = json!(12500);
        let clock = json!({"schema":"jetstreamer-epoch144-serialized-snapshot-clock-v1","input_sha256":SNAPSHOT,
            "pinned_typed_serialized_clock_only":true,"native_bank_restored":false,"replay_launch_authorized":false,
            "publication_authorized":false,"census":{"clock":clock_fields}});
        (manifest, pass, clock)
    }
    #[test]
    fn exact_prefix_and_clock_match_without_rounding_consensus_u64() {
        let (m, p, c) = sources();
        let e = expectation(&m, &p, &c).unwrap();
        assert_eq!(e.capitalization, 488586979125186779u64);
        for key in [
            "slot",
            "bank_hash",
            "last_blockhash",
            "capitalization",
            "transaction_count",
            "tick_height",
            "complete",
        ] {
            let mut bad = c.clone();
            bad["census"]["clock"][key] = json!("wrong");
            assert!(expectation(&m, &p, &bad).is_err(), "{key}");
        }
        for key in [
            "validation",
            "archive_sha256",
            "worker_executable_sha256",
            "canonical_checksum_sidecar_absent",
        ] {
            let mut bad = p.clone();
            bad[key] = json!("wrong");
            assert!(expectation(&m, &bad, &c).is_err(), "{key}");
        }
    }
    #[test]
    fn plans_cannot_enable_replay_or_borrow140() {
        assert!(serde_json::from_value::<Plan>(json!({"allow_replay":true})).is_err());
        assert!(expectation(&json!({"epoch":140}), &json!({}), &json!({})).is_err());
        assert_eq!(PEAK, 42949672960);
    }
}
