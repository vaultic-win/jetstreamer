//! Exact private epoch 228 candidate; no ordinary registry or publication route.
use crate::{
    BankHashExpectation, QualificationPlan, ReadyEntry, compatibility as c, historical as h,
};
use jetstreamer_historical_protocol as protocol;
use solana_hash::Hash;
use std::{
    collections::BTreeMap,
    ops::Range,
    path::Path,
    sync::{
        OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};

pub(crate) const BOOTSTRAP: u64 = 98_495_291;
const FIRST: u64 = 98_496_000;
const END: u64 = 98_928_278;
pub(crate) const BACKEND: &str = "solana-v1.6.20-epoch228-called-program-demotion-candidate";
const BOOT_ACCOUNTS: &str = "GfiRSgpC1qvH3uxVd9VAtYZ6qKM8fcdkyoyAkhF7izLq";
const TERMINAL_ACCOUNTS: &str = "6Ec1ZPL4kEMFLU2qAsRfrbmYnEhm8pL77Xt1PoBhyGra";
const SNAPSHOT_SHA: &str = "da26bd1b4b3b93be74c9dae28d1d982f821474333aa06e87f32dfa83342915f3";
static INITIALIZED: AtomicBool = AtomicBool::new(false);
static EXACT_GOVERNANCE: AtomicBool = AtomicBool::new(false);

#[cfg(any(
    feature = "epoch136-actual-input-diagnostic",
    feature = "epoch140-native-restore-diagnostic",
    original_entry_replay,
    feature = "epoch144-checkpoint-continuation-diagnostic",
    feature = "epoch144-native-restore-diagnostic",
    feature = "epoch163-first-output128-diagnostic",
    feature = "epoch169-v1-5-8-diagnostic",
    feature = "epoch203-checkpoint-continuation-diagnostic",
    feature = "epoch203-native-restore-diagnostic",
    feature = "epoch205-native-restore-diagnostic",
    feature = "epoch207-singleton-qualification",
    feature = "epoch213-checkpoint-continuation-diagnostic",
    feature = "epoch223-v1-6-20-prefix-qualification",
    feature = "epoch223-v1-6-25-qualification",
    feature = "epoch224-account-delta-diagnostic",
    feature = "epoch224-v1-6-25-diagnostic",
    feature = "epoch224-v1-6-25-qualification",
    feature = "epoch225-v1-6-25-diagnostic",
    feature = "epoch225-v1-6-25-qualification",
    feature = "epochs209-212-singleton-qualification"
))]
compile_error!("epoch 228 demotion requires its own exclusive private parent build");

fn digest(text: &str) -> Result<[u8; 32], String> {
    if text.len() != 64
        || text.bytes().all(|b| b == b'0')
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("epoch 228 requires an actual nonzero lowercase artifact SHA-256".into());
    }
    let mut out = [0; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}
const WORKER_SHA: &str = "16d4b15881979bb7d65a0f49408580d4508b451a5953f35cbb60505d2e3cee00";

pub(crate) fn validate_worker_digest(actual: [u8; 32]) -> Result<(), String> {
    if actual != digest(WORKER_SHA)? {
        return Err("epoch 228 worker digest differs before spawn".into());
    }
    Ok(())
}
pub(crate) fn selected(range: &Range<u64>) -> bool {
    range.end == END + 1 && [BOOTSTRAP + 1, FIRST].contains(&range.start)
}
pub(crate) fn select(
    range: Range<u64>,
    focused: bool,
    allow: bool,
) -> Result<c::RuntimeSelection, String> {
    if !focused || !allow || !selected(&range) {
        return Err("epoch 228 candidate requires its exact focused cold/root-tail span".into());
    }
    static DESCRIPTOR: OnceLock<c::RuntimeDescriptor> = OnceLock::new();
    let descriptor = DESCRIPTOR.get_or_init(|| {
        let mut value = c::SOLANA_V1_6_20_RUNTIME;
        value.identity.name = BACKEND;
        value.worker = Some(c::WorkerExecutable {
            identity: "jetstreamer-historical-worker-v1-6-20",
            environment_override: "JETSTREAMER_HISTORICAL_WORKER_EPOCH228_DEMOTION",
            default_manifest_relative_path: "/nonexistent/epoch228-demotion-requires-actual-bound-worker",
        });
        value
    });
    Ok(c::RuntimeSelection {
        backend: c::RuntimeBackend::SolanaV1_6_20,
        descriptor,
        admission: c::AdmissionLevel::Candidate,
    })
}
pub(crate) fn worker_profile(
    descriptor: &c::RuntimeDescriptor,
) -> Result<h::WorkerProfile, String> {
    if descriptor.identity.name != BACKEND
        || descriptor.identity.revision != c::SOLANA_V1_6_20_REVISION
        || descriptor.worker.is_none_or(|w| {
            w.environment_override != "JETSTREAMER_HISTORICAL_WORKER_EPOCH228_DEMOTION"
        })
    {
        return Err("epoch 228 descriptor cannot borrow another worker identity".into());
    }
    Ok(h::WorkerProfile {
        backend_id: BACKEND,
        ..h::SOLANA_V1_6_20_CANDIDATE
    })
}
pub(crate) fn entrypoint(args: &[String]) -> Result<(), String> {
    if args.len() == 1 && args[0] == "--epoch228-demotion-capability" {
        return Ok(());
    }
    if !matches!(args.first().map(String::as_str), Some("228" | "228-228"))
        || args.iter().any(|a| {
            a.contains("recover")
                || a.contains("cohort")
                || a.contains("continuation")
                || a.contains("epoch223")
                || a.contains("epoch227")
                || a.starts_with("--range-info")
                || a.contains("handoff")
                || a.contains("inherited")
        })
    {
        return Err(
            "private epoch 228 build rejects ordinary, foreign, inherited and recovery entrypoints"
                .into(),
        );
    }
    Ok(())
}
pub(crate) fn launch(
    first: u64,
    last: u64,
    focused: Option<(u64, u64)>,
    cohort: bool,
    recovery: bool,
    paths: Option<(&Path, &Path, &Path)>,
) -> Result<(), String> {
    if (first, last, focused, cohort, recovery) != (228, 228, Some((BOOTSTRAP, END)), false, false)
    {
        return Err(
            "epoch 228 requires exactly 708 warmup slots, full epoch and 279 private tail slots"
                .into(),
        );
    }
    let (ledger, output, scratch) = paths.ok_or("explicit private epoch 228 paths required")?;
    let root = ledger.parent().ok_or("epoch 228 ledger root absent")?;
    let name = root
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.strip_prefix("qualification-228-demotion-root-tail-"));
    if root.parent() != Some(Path::new("/home/ubuntu/.jetstreamer-private"))
        || name.is_none_or(|n| {
            n.is_empty() || !n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
        || ledger != root.join("ledger")
        || scratch != root.join("scratch")
        || output != root.join("output/epoch-228-through-98928278.jet")
    {
        return Err(
            "epoch 228 must preserve old attempts and use its own exact fresh namespace".into(),
        );
    }
    Ok(())
}
pub(crate) fn fresh_filesystem(ledger: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let root = ledger.parent().ok_or("private root missing")?;
    let m = std::fs::symlink_metadata(root).map_err(|e| e.to_string())?;
    if !m.is_dir()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
        || root.canonicalize().map_err(|e| e.to_string())? != root
    {
        return Err("epoch 228 requires a canonical owner-only private root".into());
    }
    for child in ["ledger", "scratch", "output"] {
        let path = root.join(child);
        match std::fs::symlink_metadata(&path) {
            Ok(meta) => {
                if !meta.is_dir()
                    || meta.uid() != m.uid()
                    || meta.mode() & 0o077 != 0
                    || path.canonicalize().map_err(|e| e.to_string())? != path
                {
                    return Err("epoch 228 rejects aliased or unsafe private children".into());
                }
                if child == "scratch"
                    && std::fs::read_dir(&path)
                        .map_err(|e| e.to_string())?
                        .next()
                        .is_some()
                {
                    return Err("epoch 228 refuses occupied scratch from any prior attempt".into());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    for name in [
        "epoch-228-through-98928278.jet",
        "epoch-228-through-98928278.jet.sha256",
        "epoch-228-through-98928278.jet.segment.json",
        "epoch-228.jet",
        "epoch-228.jet.sha256",
    ] {
        match std::fs::symlink_metadata(root.join("output").join(name)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err("epoch 228 refuses existing or aliased outputs/sidecars".into()),
        }
    }
    Ok(())
}
pub(crate) fn expectations(
    expected: BTreeMap<u64, BankHashExpectation>,
    plan: QualificationPlan,
    snapshot: &Path,
    bootstrap: c::BootstrapState,
) -> Result<BTreeMap<u64, BankHashExpectation>, String> {
    if (
        plan.epoch,
        plan.bootstrap_slot,
        plan.replay_start,
        plan.output_slot_start,
        plan.end_inclusive,
    ) != (228, BOOTSTRAP, BOOTSTRAP + 1, FIRST, END)
    {
        return Err("epoch 228 checkpoint span changed".into());
    }
    let (slot, value) = crate::snapshot_path_expectation(snapshot, bootstrap)?;
    let boot =
        BankHashExpectation::LegacyAccountsHash(BOOT_ACCOUNTS.parse().map_err(|e| format!("{e}"))?);
    let terminal = BankHashExpectation::LegacyAccountsHash(
        TERMINAL_ACCOUNTS.parse().map_err(|e| format!("{e}"))?,
    );
    if slot != BOOTSTRAP
        || value != boot
        || expected.len() != 2
        || expected.get(&BOOTSTRAP) != Some(&boot)
        || expected.get(&END) != Some(&terminal)
    {
        return Err(
            "epoch 228 requires both independent real roots; no invented cut checkpoint".into(),
        );
    }
    Ok(expected)
}
pub(crate) fn bind_initialization(
    mut init: h::HistoricalInitialization,
) -> Result<h::HistoricalInitialization, String> {
    match &mut init {
        h::HistoricalInitialization::SnapshotArchive(s)
            if s.expected_slot == BOOTSTRAP
                && Hash::new_from_array(s.expected_accounts_hash).to_string() == BOOT_ACCOUNTS =>
        {
            s.expected_archive_sha256 = Some(digest(SNAPSHOT_SHA)?);
            s.expected_archive_size = Some(10_510_540_911);
        }
        _ => return Err("epoch 228 requires exact digest-bound cold snapshot".into()),
    }
    Ok(init)
}
pub(crate) fn initialize(client: &mut h::HistoricalRuntimeClient) -> Result<(), String> {
    validate_worker_digest(client.executable_sha256())?;
    if client.initialized().source != h::HistoricalInitializedSource::SnapshotArchive
        || client.initialized().ticks_per_slot != 64
        || client.initialized().slot != BOOTSTRAP
    {
        return Err("epoch 228 bootstrap changed".into());
    }
    let cp = client
        .freeze_checkpoint(BOOTSTRAP)
        .map_err(|e| e.to_string())?;
    // Independent original cold tuple is a comparison target, never a reusable
    // qualification receipt for this semantic worker. Every integer is exact.
    if cp.slot != BOOTSTRAP
        || !cp.slot_complete
        || !cp.writes.is_empty()
        || Hash::new_from_array(cp.accounts_hash).to_string() != BOOT_ACCOUNTS
        || Hash::new_from_array(cp.bank_hash).to_string()
            != "3bAzCpbDvGKVrLQTP1hwEdibg6j4DYucpkxwQ3FvkCb2"
        || Hash::new_from_array(cp.last_blockhash).to_string()
            != "9xcoJhnYB4FJjJS3xRGytzb6i8epLY7i3cdzDAFpAwfR"
        || cp.capitalization != 504_915_797_589_943_503
        || cp.transaction_count != 29_954_968_857
        || cp.tick_height != 6_303_698_688
        || cp.last_blockhash != client.initialized().last_blockhash
        || cp.next_write_version != client.initialized().next_write_version
        || cp.next_write_version != 113_087_684_591
    {
        return Err(
            "epoch 228 new worker cold tuple differs; old retry tuple is not relaxed".into(),
        );
    }
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Err("epoch 228 cannot reuse an initialized session".into());
    }
    log::info!(
        "epoch 228 demotion cold native tuple verified slot={BOOTSTRAP} replay_entries=0 bootstrap_writes=0"
    );
    Ok(())
}
pub(crate) fn outcomes(
    entry: &ReadyEntry,
    outcomes: &[h::HistoricalTransactionOutcome],
) -> Result<(), String> {
    if entry.slot != 98_505_585 {
        return Ok(());
    }
    for (offset, (tx, result)) in entry.txs.iter().zip(outcomes).enumerate() {
        if entry.start_index + offset != 175 {
            continue;
        }
        let error = protocol::TransactionError::InstructionError {
            instruction_index: 0,
            error: protocol::InstructionError::PrivilegeEscalation,
        };
        if !INITIALIZED.load(Ordering::SeqCst)
            || entry.entry_index != 192
            || result.error.as_ref() != Some(&error)
            || tx.expected_status.as_ref() != Some(&Err(h::denormalize_transaction_error(&error)))
            || bincode::serialize(&tx.tx)
                .map_err(|e| e.to_string())?
                .as_slice()
                != include_bytes!("../../historical-runtime/fixtures/epoch228-98505585-tx175.bin")
        {
            return Err("epoch 228 exact Governance wire must reproduce canonical native PrivilegeEscalation".into());
        }
        if EXACT_GOVERNANCE.swap(true, Ordering::SeqCst) {
            return Err("epoch 228 original transaction observed more than once".into());
        }
        log::info!(
            "epoch 228 exact Governance native PrivilegeEscalation verified slot=98505585 entry=192 transaction=175"
        );
    }
    Ok(())
}
pub(crate) fn checkpoint(cp: &h::HistoricalCheckpoint) -> Result<(), String> {
    if cp.slot == END
        && (!cp.slot_complete
            || !EXACT_GOVERNANCE.load(Ordering::SeqCst)
            || Hash::new_from_array(cp.accounts_hash).to_string() != TERMINAL_ACCOUNTS)
    {
        return Err(
            "epoch 228 terminal requires exact canonical failed transaction and real final root"
                .into(),
        );
    }
    if cp.slot == END {
        log::info!(
            "epoch 228 demotion terminal root verified slot={END} retained_private_tail_slots=279 publication_authorized=false"
        );
    }
    Ok(())
}
pub(crate) fn require_natural_close(outcome: h::HistoricalShutdownOutcome) -> Result<(), String> {
    match outcome {
        h::HistoricalShutdownOutcome::Reaped {
            worker_pid,
            forced: false,
        } => {
            log::info!("epoch 228 qualification worker reaped after natural exit pid={worker_pid}");
            Ok(())
        }
        other => Err(format!(
            "epoch 228 qualification worker lacked a natural exit: {other:?}"
        )),
    }
}
pub(crate) fn capability() -> Result<serde_json::Value, String> {
    let selection = select(FIRST..END + 1, true, true)?;
    worker_profile(selection.descriptor)?;
    let executable = crate::configured_historical_worker_executable(selection.descriptor)?;
    let actual = h::measure_executable_sha256(&executable).map_err(|e| e.to_string())?;
    validate_worker_digest(actual)?;
    Ok(
        serde_json::json!({"schema":"jetstreamer-private-epoch228-demotion-parent-capability-v1",
        "epoch":228,"runtime_profile":BACKEND,"worker_sha256":WORKER_SHA,
        "worker_executable":executable,"bootstrap_slot":BOOTSTRAP,"output_slot_start":FIRST,
        "terminal_slot":END,"warmup_slots":708,"private_tail_slots":279,
        "native_input_qualified":false,"worker_spawned":false,"replay_entries":0,
        "archive_created":false,"publication_authorized":false,"runtime_promotion_authorized":false,"r2_mutations":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn qualification_requires_a_natural_reap_after_shutdown() {
        use h::HistoricalShutdownOutcome::*;
        assert!(
            require_natural_close(Reaped {
                worker_pid: 42,
                forced: false
            })
            .is_ok()
        );
        for outcome in [
            Reaped {
                worker_pid: 42,
                forced: true,
            },
            ReapPending { worker_pid: 42 },
            AlreadyClosed,
        ] {
            assert!(require_natural_close(outcome).is_err());
        }
    }
    #[test]
    fn exact_private_route_cannot_promote_ordinary_or_epoch229() {
        assert!(select(FIRST..END + 1, true, true).is_ok());
        for (range, focused, allow) in [
            (FIRST..END + 2, true, true),
            (FIRST..END + 1, false, true),
            (FIRST..END + 1, true, false),
            (98_928_000..99_360_000, true, true),
        ] {
            assert!(select(range, focused, allow).is_err());
        }
        assert!(worker_profile(&c::SOLANA_V1_6_20_RUNTIME).is_err());
        assert_ne!(c::SOLANA_V1_6_20_RUNTIME.identity.name, BACKEND);
    }
    #[test]
    fn both_real_roots_are_required_without_an_invented_epoch_cut() {
        let plan = QualificationPlan {
            epoch: 228,
            bootstrap_slot: BOOTSTRAP,
            replay_start: BOOTSTRAP + 1,
            output_slot_start: FIRST,
            end_inclusive: END,
        };
        let snapshot = Path::new(
            "/sealed/snapshot-98495291-GfiRSgpC1qvH3uxVd9VAtYZ6qKM8fcdkyoyAkhF7izLq.tar.zst",
        );
        let expected: BTreeMap<_, _> = [(BOOTSTRAP, BOOT_ACCOUNTS), (END, TERMINAL_ACCOUNTS)]
            .into_iter()
            .map(|(slot, hash)| {
                (
                    slot,
                    BankHashExpectation::LegacyAccountsHash(hash.parse().unwrap()),
                )
            })
            .collect();
        let bootstrap = c::SOLANA_V1_6_20_RUNTIME.bootstrap;
        assert!(expectations(expected.clone(), plan, snapshot, bootstrap).is_ok());
        for removed in [BOOTSTRAP, END] {
            let mut missing = expected.clone();
            missing.remove(&removed);
            assert!(expectations(missing, plan, snapshot, bootstrap).is_err());
        }
        let mut invented = expected;
        invented.insert(
            98_927_999,
            BankHashExpectation::LegacyAccountsHash(TERMINAL_ACCOUNTS.parse().unwrap()),
        );
        assert!(expectations(invented, plan, snapshot, bootstrap).is_err());
    }

    #[test]
    fn original_worker_and_invalid_hashes_fail_closed() {
        assert!(validate_worker_digest(digest(WORKER_SHA).unwrap()).is_ok());
        assert!(
            validate_worker_digest(
                digest("1bfa8d51d44729c75db7ffe5d466cec9d902216d9362a6efb129bf927ca85673").unwrap()
            )
            .is_err()
        );
        for bad in [
            "",
            "__ACTUAL_CAPTURED_SHA__",
            &"0".repeat(64),
            &"A".repeat(64),
        ] {
            assert!(digest(bad).is_err());
        }
    }
    #[test]
    fn original_success_disagrees_with_the_signed_recorded_failure() {
        let rpc: serde_json::Value = serde_json::from_str(include_str!(
            "../../historical-runtime/fixtures/epoch228-98505585-tx175.finalized.json"
        ))
        .unwrap();
        let recorded = &rpc["result"];
        assert_eq!(recorded["slot"], 98_505_585);
        assert_eq!(recorded["transactionIndex"], 175);
        let message =
            include_bytes!("../../historical-runtime/fixtures/epoch228-98505585-tx175.bin");
        let tx: solana_transaction::versioned::VersionedTransaction =
            bincode::deserialize(message).unwrap();
        let expected = protocol::TransactionError::InstructionError {
            instruction_index: 0,
            error: protocol::InstructionError::PrivilegeEscalation,
        };
        let source_error = serde_json::from_value(recorded["meta"]["err"].clone()).unwrap();
        assert_eq!(source_error, h::denormalize_transaction_error(&expected));
        let signature = Some(*tx.signatures[0].as_array());
        let entry = ReadyEntry {
            slot: 98_505_585,
            entry_index: 192,
            start_index: 175,
            num_hashes: 1,
            hash: Hash::default(),
            tx_count: 1,
            txs: vec![crate::ScheduledTransaction {
                tx,
                expected_status: Some(Err(source_error)),
                reconstruct_fee: false,
                status_meta: Default::default(),
            }],
        };
        let mut actual = h::HistoricalTransactionOutcome {
            signature,
            error: None,
            fee: 0,
        };
        INITIALIZED.store(true, Ordering::SeqCst);
        assert!(outcomes(&entry, std::slice::from_ref(&actual)).is_err());
        assert!(!EXACT_GOVERNANCE.load(Ordering::SeqCst));
        actual.error = Some(expected);
        outcomes(&entry, std::slice::from_ref(&actual)).unwrap();
        assert!(EXACT_GOVERNANCE.swap(false, Ordering::SeqCst));
        INITIALIZED.store(false, Ordering::SeqCst);
    }
    #[test]
    fn old_attempts_foreign_scopes_and_recovery_entrypoints_are_rejected() {
        for first in [
            "229",
            "228-229",
            "--failed-prefix220-recover",
            "--post-update-capacity-probe",
        ] {
            assert!(entrypoint(&[first.into()]).is_err());
        }
        assert!(entrypoint(&["--epoch228-demotion-capability".into()]).is_ok());
        let root = Path::new(
            "/home/ubuntu/.jetstreamer-private/qualification-228-demotion-root-tail-test",
        );
        let paths = Some((
            root.join("ledger"),
            root.join("output/epoch-228-through-98928278.jet"),
            root.join("scratch"),
        ));
        let (l, o, s) = paths.as_ref().unwrap();
        assert!(
            launch(
                228,
                228,
                Some((BOOTSTRAP, END)),
                false,
                false,
                Some((l, o, s))
            )
            .is_ok()
        );
        assert!(
            launch(
                228,
                228,
                Some((BOOTSTRAP, 98_927_999)),
                false,
                false,
                Some((l, o, s))
            )
            .is_err()
        );
        assert!(
            launch(
                228,
                229,
                Some((BOOTSTRAP, END)),
                false,
                false,
                Some((l, o, s))
            )
            .is_err()
        );
        assert!(
            launch(
                228,
                228,
                Some((BOOTSTRAP, END)),
                false,
                true,
                Some((l, o, s))
            )
            .is_err()
        );
    }
}
