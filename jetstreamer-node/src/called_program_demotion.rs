//! Private called-program demotion replays through independently verified accounts roots.
use crate::{
    BankHashExpectation, QualificationPlan, ReadyEntry, compatibility as c, historical as h,
};
use jetstreamer_node::segment_manifest::sha256_hex_string;
use solana_hash::Hash;
use std::{
    collections::BTreeMap,
    ops::Range,
    os::unix::fs::MetadataExt,
    path::Path,
    sync::{
        OnceLock,
        atomic::{AtomicU8, Ordering},
    },
};

#[cfg(all(
    feature = "epoch229-called-program-demotion-qualification",
    feature = "epoch230-called-program-demotion-qualification",
))]
compile_error!("choose one called-program demotion qualification epoch");

#[cfg(all(
    feature = "epoch231-called-program-demotion-qualification",
    any(
        feature = "epoch229-called-program-demotion-qualification",
        feature = "epoch230-called-program-demotion-qualification",
    ),
))]
compile_error!("epoch 231 requires its own called-program demotion qualification build");

#[cfg_attr(
    feature = "epoch229-called-program-demotion-qualification",
    path = "called_program_demotion/epoch229.rs"
)]
#[cfg_attr(
    feature = "epoch231-called-program-demotion-qualification",
    path = "called_program_demotion/epoch231.rs"
)]
#[cfg_attr(
    feature = "epoch230-vote-boundary-demotion-qualification",
    path = "called_program_demotion/epoch230_vote_boundary.rs"
)]
#[cfg_attr(
    not(any(
        feature = "epoch229-called-program-demotion-qualification",
        feature = "epoch231-called-program-demotion-qualification",
        feature = "epoch230-vote-boundary-demotion-qualification",
    )),
    path = "called_program_demotion/epoch230.rs"
)]
mod profile;
use profile::*;
pub(crate) use profile::{BACKEND, BOOTSTRAP, CAPABILITY_ARG, DIVERGENT_SLOT, EPOCH};

const VOTE_BOUNDARY: bool = cfg!(feature = "epoch230-vote-boundary-demotion-qualification");

#[cfg(any(
    original_entry_replay,
    feature = "epoch136-actual-input-diagnostic",
    feature = "epoch163-first-output128-diagnostic",
    feature = "epoch169-v1-5-8-diagnostic",
    feature = "epoch140-native-restore-diagnostic",
    feature = "epoch144-checkpoint-continuation-diagnostic",
    feature = "epoch144-native-restore-diagnostic",
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
    feature = "epoch226-checkpoint-continuation-diagnostic",
    feature = "epoch228-called-program-demotion-qualification",
    feature = "epochs209-212-singleton-qualification",
))]
compile_error!("called-program demotion requires its own private parent build");

pub(crate) fn validate_worker_digest(actual: [u8; 32]) -> Result<(), String> {
    if actual == [0; 32] || WORKER_SHA != Some(sha256_hex_string(&actual).as_str()) {
        return Err(format!(
            "epoch {EPOCH} requires the candidate worker SHA-256 pinned at build time"
        ));
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
        return Err(format!(
            "epoch {EPOCH} demotion requires the exact focused replay range"
        ));
    }
    static DESCRIPTOR: OnceLock<c::RuntimeDescriptor> = OnceLock::new();
    let descriptor = DESCRIPTOR.get_or_init(|| {
        let mut value = c::SOLANA_V1_6_20_RUNTIME;
        value.identity.name = BACKEND;
        value.worker = Some(c::WorkerExecutable {
            identity: "jetstreamer-historical-worker-v1-6-20",
            environment_override: WORKER_ENV,
            default_manifest_relative_path: "/nonexistent/demotion-requires-bound-worker",
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
        || descriptor
            .worker
            .is_none_or(|worker| worker.environment_override != WORKER_ENV)
    {
        return Err(format!("epoch {EPOCH} candidate worker identity differs"));
    }
    Ok(h::WorkerProfile {
        backend_id: BACKEND,
        ..h::SOLANA_V1_6_20_CANDIDATE
    })
}

pub(crate) fn entrypoint(args: &[String]) -> Result<(), String> {
    if args.len() == 1 && matches!(args[0].as_str(), "-h" | "--help" | CAPABILITY_ARG) {
        return Ok(());
    }
    if !args
        .first()
        .is_some_and(|epoch| EPOCH_ARGS.contains(&epoch.as_str()))
        || args.iter().filter(|arg| arg.starts_with("--")).any(|arg| {
            [
                "recover",
                "cohort",
                "continuation",
                "handoff",
                "inherited",
                "range-info",
                "epoch223",
                "epoch227",
                "epoch228",
                "export",
            ]
            .iter()
            .any(|option| arg.contains(option))
        })
    {
        return Err(format!(
            "epoch {EPOCH} requires its focused private entrypoint"
        ));
    }
    Ok(())
}

pub(crate) fn launch(
    first: u64,
    last: u64,
    qualification: Option<QualificationPlan>,
    incompatible_mode: bool,
    paths: Option<(&Path, &Path, &Path)>,
) -> Result<(), String> {
    let exact_plan = qualification.is_some_and(|p| {
        (
            p.epoch,
            p.bootstrap_slot,
            p.replay_start,
            p.output_slot_start,
            p.end_inclusive,
        ) == (EPOCH, BOOTSTRAP, BOOTSTRAP + 1, FIRST, END)
    });
    if (first, last) != (EPOCH, EPOCH) || !exact_plan || incompatible_mode {
        return Err(format!(
            "epoch {EPOCH} candidate requires its exact cold-through-root invocation"
        ));
    }
    let (ledger, output, scratch) =
        paths.ok_or_else(|| format!("explicit private epoch {EPOCH} paths required"))?;
    let root = Path::new(RUN_ROOT);
    let ledger_path = root.join("output");
    let scratch_path = if VOTE_BOUNDARY {
        root.join("scratch")
    } else {
        ledger_path.clone()
    };
    if ledger != ledger_path || scratch != scratch_path || output != ledger_path.join(OUTPUT) {
        return Err(format!(
            "epoch {EPOCH} requires the guarded ledger, scratch and output"
        ));
    }
    Ok(())
}

pub(crate) fn fresh_filesystem(ledger: &Path) -> Result<(), String> {
    let root = Path::new(RUN_ROOT);
    let state = root.join("state");
    if std::env::var_os(crate::PRIVATE_RUN_ROOT_ENV).as_deref() != Some(state.as_os_str()) {
        return Err(format!(
            "epoch {EPOCH} requires the guarded private run state"
        ));
    }
    let indexes = ledger.join("compact-indexes");
    let index_epochs = if VOTE_BOUNDARY {
        EPOCH..=EPOCH
    } else if cfg!(feature = "epoch230-final-tail-demotion-qualification") {
        EPOCH..=EPOCH + 1
    } else {
        EPOCH - 1..=EPOCH
    };
    let scratch = root.join("scratch");
    let index_dirs = index_epochs.map(|epoch| indexes.join(epoch.to_string()));
    let dirs = [root, ledger, state.as_path(), indexes.as_path()]
        .into_iter()
        .map(Path::to_path_buf)
        .chain(index_dirs)
        .chain(VOTE_BOUNDARY.then(|| scratch.clone()));
    for path in dirs {
        let metadata = std::fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
            || path.canonicalize().map_err(|error| error.to_string())? != path
        {
            return Err(format!(
                "epoch {EPOCH} requires an owner-only directory at {}",
                path.display()
            ));
        }
    }
    let genesis = ledger.join("genesis.tar.bz2");
    let metadata = std::fs::symlink_metadata(&genesis).map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.mode() & 0o222 != 0 {
        return Err(format!(
            "epoch {EPOCH} requires the prebound read-only genesis"
        ));
    }
    for entry in std::fs::read_dir(ledger).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        if entry.path() != genesis && entry.path() != indexes {
            return Err(format!(
                "epoch {EPOCH} refuses existing output {}",
                entry.path().display()
            ));
        }
    }
    if std::fs::read_dir(state)
        .map_err(|error| error.to_string())?
        .next()
        .is_some()
    {
        return Err(format!("epoch {EPOCH} refuses occupied private run state"));
    }
    if VOTE_BOUNDARY
        && std::fs::read_dir(scratch)
            .map_err(|error| error.to_string())?
            .next()
            .is_some()
    {
        return Err(format!("epoch {EPOCH} refuses occupied replay scratch"));
    }
    Ok(())
}

pub(crate) fn expectations(
    expected: BTreeMap<u64, BankHashExpectation>,
    plan: QualificationPlan,
    snapshot: &Path,
    bootstrap: c::BootstrapState,
) -> Result<BTreeMap<u64, BankHashExpectation>, String> {
    let boot = BankHashExpectation::LegacyAccountsHash(
        BOOT_ACCOUNTS.parse().map_err(|error| format!("{error}"))?,
    );
    let terminal = BankHashExpectation::LegacyAccountsHash(
        TERMINAL_ACCOUNTS
            .parse()
            .map_err(|error| format!("{error}"))?,
    );
    #[cfg(feature = "epoch230-final-tail-demotion-qualification")]
    {
        let canonical = BankHashExpectation::LegacyAccountsHash(
            EPOCH230_ROOT
                .1
                .parse()
                .map_err(|error| format!("{error}"))?,
        );
        if expected.get(&EPOCH230_ROOT.0) != Some(&canonical) {
            return Err(
                "epoch 230 requires its registered checkpoint during final-tail replay".into(),
            );
        }
    }
    let root_count = if cfg!(feature = "epoch230-final-tail-demotion-qualification") {
        3
    } else {
        2
    };
    if (plan.bootstrap_slot, plan.end_inclusive) != (BOOTSTRAP, END)
        || crate::snapshot_path_expectation(snapshot, bootstrap)? != (BOOTSTRAP, boot)
        || expected.len() != root_count
        || expected.get(&BOOTSTRAP) != Some(&boot)
        || expected.get(&END) != Some(&terminal)
    {
        return Err(format!(
            "epoch {EPOCH} requires the {root_count} independently pinned snapshot roots"
        ));
    }
    Ok(expected)
}

pub(crate) fn bind_initialization(
    mut initialization: h::HistoricalInitialization,
) -> Result<h::HistoricalInitialization, String> {
    let h::HistoricalInitialization::SnapshotArchive(snapshot) = &mut initialization else {
        return Err(format!("epoch {EPOCH} requires the exact cold snapshot"));
    };
    if snapshot.expected_slot != BOOTSTRAP
        || Hash::new_from_array(snapshot.expected_accounts_hash).to_string() != BOOT_ACCOUNTS
    {
        return Err(format!("epoch {EPOCH} cold snapshot commitment differs"));
    }
    let mut sha256 = [0; 32];
    for (index, byte) in sha256.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&SNAPSHOT_SHA[index * 2..index * 2 + 2], 16)
            .map_err(|error| error.to_string())?;
    }
    snapshot.expected_archive_sha256 = Some(sha256);
    snapshot.expected_archive_size = Some(SNAPSHOT_BYTES);
    Ok(initialization)
}

pub(crate) fn validate_initialized(client: &h::HistoricalRuntimeClient) -> Result<(), String> {
    validate_worker_digest(client.executable_sha256())?;
    let initialization = client.initialized();
    if initialization.source != h::HistoricalInitializedSource::SnapshotArchive
        || initialization.slot != BOOTSTRAP
        || initialization.ticks_per_slot != 64
        || initialization.next_write_version != BOOT_WRITE_VERSION
    {
        return Err(format!("epoch {EPOCH} cold worker initialization differs"));
    }
    Ok(())
}

#[derive(Default)]
pub(crate) struct Verification {
    stage: AtomicU8,
}

impl Verification {
    fn advance(&self, previous: u8, next: u8) -> Result<(), String> {
        self.stage
            .compare_exchange(previous, next, Ordering::SeqCst, Ordering::SeqCst)
            .map(|_| ())
            .map_err(|actual| {
                format!(
                    "epoch {EPOCH} qualification stage {actual} differs from expected {previous}"
                )
            })
    }

    pub(crate) fn outcomes(
        &self,
        entry: &ReadyEntry,
        outcomes: &[h::HistoricalTransactionOutcome],
    ) -> Result<(), String> {
        if entry.slot != DIVERGENT_SLOT {
            return Ok(());
        }
        let Some(offset) = TRANSACTION_INDEX.checked_sub(entry.start_index) else {
            return Ok(());
        };
        let Some(transaction) = entry.txs.get(offset) else {
            return Ok(());
        };
        let actual = outcomes
            .get(offset)
            .ok_or("called-program demotion outcome missing")?;
        if transaction.expected_status != Some(Ok(()))
            || actual.error.is_some()
            || actual.fee != 5_000
            || bincode::serialize(&transaction.tx).map_err(|error| error.to_string())? != WIRE
        {
            return Err(format!(
                "epoch {EPOCH} transaction {TRANSACTION_INDEX} differs from its signed successful record"
            ));
        }
        self.advance(1, 2)?;
        log::info!(
            "epoch {EPOCH} verified exact signed transaction {TRANSACTION_INDEX} at slot {DIVERGENT_SLOT}"
        );
        Ok(())
    }

    pub(crate) fn checkpoint(&self, checkpoint: &h::HistoricalCheckpoint) -> Result<(), String> {
        let accounts = Hash::new_from_array(checkpoint.accounts_hash);
        let bank = Hash::new_from_array(checkpoint.bank_hash);
        match checkpoint.slot {
            BOOTSTRAP => {
                if !checkpoint.slot_complete
                    || !checkpoint.writes.is_empty()
                    || accounts.to_string() != BOOT_ACCOUNTS
                    || bank.to_string() != BOOT_BANK
                    || Hash::new_from_array(checkpoint.last_blockhash).to_string() != BOOT_POH
                    || checkpoint.capitalization != BOOT_CAPITALIZATION
                    || checkpoint.transaction_count != BOOT_TRANSACTIONS
                    || checkpoint.tick_height != BOOT_TICK_HEIGHT
                    || checkpoint.next_write_version != BOOT_WRITE_VERSION
                {
                    return Err(format!(
                        "epoch {EPOCH} candidate differs from the pinned cold checkpoint"
                    ));
                }
                self.advance(0, 1)?;
            }
            DIVERGENT_SLOT => {
                if !checkpoint.slot_complete || bank.to_string() != DIVERGENT_BANK {
                    return Err(format!(
                        "epoch {EPOCH} bank hash at {DIVERGENT_SLOT} is {bank}, expected {DIVERGENT_BANK}"
                    ));
                }
                self.advance(2, 3)?;
            }
            END => {
                if !checkpoint.slot_complete || accounts.to_string() != TERMINAL_ACCOUNTS {
                    return Err(format!(
                        "epoch {EPOCH} candidate differs from the pinned terminal root"
                    ));
                }
                self.advance(3, 4)?;
            }
            _ => {}
        }
        Ok(())
    }

    pub(crate) fn require_natural_close(
        &self,
        outcome: h::HistoricalShutdownOutcome,
    ) -> Result<(), String> {
        if self.stage.load(Ordering::SeqCst) != 4 {
            return Err(format!(
                "epoch {EPOCH} qualification ended before the terminal root passed"
            ));
        }
        match outcome {
            h::HistoricalShutdownOutcome::Reaped { forced: false, .. } => Ok(()),
            other => Err(format!(
                "epoch {EPOCH} candidate did not exit naturally: {other:?}"
            )),
        }
    }
}

pub(crate) fn capability() -> Result<serde_json::Value, String> {
    let selection = select(FIRST..END + 1, true, true)?;
    worker_profile(selection.descriptor)?;
    let executable = crate::configured_historical_worker_executable(selection.descriptor)?;
    let actual = h::measure_executable_sha256(&executable).map_err(|error| error.to_string())?;
    validate_worker_digest(actual)?;
    Ok(serde_json::json!({
        "schema": CAPABILITY_SCHEMA,
        "epoch": EPOCH,
        "runtime_profile": BACKEND,
        "worker_executable": executable,
        "worker_sha256": WORKER_SHA,
        "bootstrap_slot": BOOTSTRAP,
        "output_slot_start": FIRST,
        "bank_hash_slot": DIVERGENT_SLOT,
        "terminal_slot": END,
        "run_root": RUN_ROOT,
        "output_leaf": OUTPUT,
        "worker_spawned": false,
        "publication_authorized": false,
        "runtime_promotion_authorized": false
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_foreign_cli_and_mismatched_work_paths() {
        assert!(entrypoint(&["--help".into()]).is_ok());
        assert!(entrypoint(&[CAPABILITY_ARG.into()]).is_ok());
        assert!(entrypoint(&["201".into()]).is_err());
        assert!(entrypoint(&[EPOCH.to_string(), "--checkpoint-export=anything".into()]).is_err());

        let expected = QualificationPlan {
            epoch: EPOCH,
            bootstrap_slot: BOOTSTRAP,
            replay_start: BOOTSTRAP + 1,
            output_slot_start: FIRST,
            end_inclusive: END,
        };
        let ledger = Path::new(RUN_ROOT).join("output");
        let output = ledger.join(OUTPUT);
        let scratch = if VOTE_BOUNDARY {
            Path::new(RUN_ROOT).join("scratch")
        } else {
            ledger.clone()
        };
        let paths = Some((ledger.as_path(), output.as_path(), scratch.as_path()));
        assert!(launch(EPOCH, EPOCH, Some(expected), false, paths).is_ok());
        assert!(launch(EPOCH, EPOCH + 1, Some(expected), false, paths).is_err());
        assert!(launch(EPOCH, EPOCH, Some(expected), true, paths).is_err());
        let earlier_end = QualificationPlan {
            end_inclusive: DIVERGENT_SLOT,
            ..expected
        };
        assert!(launch(EPOCH, EPOCH, Some(earlier_end), false, paths).is_err());
        assert!(
            launch(
                EPOCH,
                EPOCH,
                Some(expected),
                false,
                Some((&ledger, &output, Path::new("/tmp")))
            )
            .is_err()
        );
        assert!(select(FIRST..END + 1, true, true).is_ok());
        assert!(select(FIRST..END + 1, false, true).is_err());
        assert!(select(FIRST..END + 1, true, false).is_err());
        assert!(worker_profile(&c::SOLANA_V1_6_20_RUNTIME).is_err());
    }

    #[cfg(feature = "epoch230-final-tail-demotion-qualification")]
    #[test]
    fn final_tail_scope_covers_230_and_requires_its_registered_root() {
        assert!(entrypoint(&["230".into()]).is_ok());
        assert!(entrypoint(&["231".into()]).is_err());
        let name = format!("snapshot-{BOOTSTRAP}-{BOOT_ACCOUNTS}.tar.zst");
        let snapshot = Path::new(&name);
        let q = crate::qualification_plan(
            230,
            230,
            Some(END),
            Some(true),
            Some(snapshot),
            Some(Path::new("epoch-hashes.txt")),
            Some(Path::new(OUTPUT)),
        )
        .unwrap()
        .unwrap();
        assert_eq!(q.output_slot_start, 99_791_405);
        assert_eq!(99_791_999 - q.output_slot_start + 1, 595);
        assert_eq!(q.end_inclusive, 99_803_089);
        let roots = [
            (BOOTSTRAP, BOOT_ACCOUNTS),
            EPOCH230_ROOT,
            (END, TERMINAL_ACCOUNTS),
        ]
        .into_iter()
        .map(|(slot, hash)| {
            (
                slot,
                BankHashExpectation::LegacyAccountsHash(hash.parse().unwrap()),
            )
        })
        .collect::<BTreeMap<_, _>>();
        let bootstrap = c::SOLANA_V1_6_20_RUNTIME.bootstrap;
        assert!(expectations(roots.clone(), q, snapshot, bootstrap).is_ok());
        let mut incomplete = roots;
        incomplete.remove(&EPOCH230_ROOT.0);
        assert!(expectations(incomplete, q, snapshot, bootstrap).is_err());
    }

    #[test]
    fn exact_transaction_and_real_root_are_required_before_natural_completion() {
        let raw = |hash: &str| hash.parse::<Hash>().unwrap().to_bytes();
        let mut checkpoint = h::HistoricalCheckpoint {
            slot: BOOTSTRAP,
            bank_hash: raw(BOOT_BANK),
            accounts_hash: raw(BOOT_ACCOUNTS),
            last_blockhash: raw(BOOT_POH),
            capitalization: BOOT_CAPITALIZATION,
            transaction_count: BOOT_TRANSACTIONS,
            tick_height: BOOT_TICK_HEIGHT,
            slot_complete: true,
            writes: vec![],
            next_write_version: BOOT_WRITE_VERSION,
        };
        let gate = Verification::default();
        let clean = h::HistoricalShutdownOutcome::Reaped {
            worker_pid: 42,
            forced: false,
        };
        assert!(gate.require_natural_close(clean.clone()).is_err());
        gate.checkpoint(&checkpoint).unwrap();
        checkpoint.slot = DIVERGENT_SLOT;
        checkpoint.bank_hash = raw(DIVERGENT_BANK);
        assert!(gate.checkpoint(&checkpoint).is_err());

        let tx = bincode::deserialize::<solana_transaction::versioned::VersionedTransaction>(WIRE)
            .unwrap();
        let signature = Some(*tx.signatures[0].as_array());
        let mut entry = ReadyEntry {
            slot: DIVERGENT_SLOT,
            entry_index: 0,
            start_index: TRANSACTION_INDEX,
            num_hashes: 1,
            hash: Hash::default(),
            tx_count: 1,
            txs: vec![crate::ScheduledTransaction {
                tx,
                expected_status: None,
                reconstruct_fee: false,
                status_meta: Default::default(),
            }],
        };
        let actual = [h::HistoricalTransactionOutcome {
            signature,
            error: None,
            fee: 5_000,
        }];
        assert!(gate.outcomes(&entry, &actual).is_err());
        entry.txs[0].expected_status = Some(Ok(()));
        gate.outcomes(&entry, &actual).unwrap();
        assert!(gate.outcomes(&entry, &actual).is_err());

        checkpoint.bank_hash = raw("8GjmZbxnM16oTkXDz3b3HpNiFbEi7hLusdBYCq5xQoyG");
        assert!(gate.checkpoint(&checkpoint).is_err());
        checkpoint.bank_hash = raw(DIVERGENT_BANK);
        gate.checkpoint(&checkpoint).unwrap();
        assert!(gate.require_natural_close(clean.clone()).is_err());

        checkpoint.slot = END;
        assert!(gate.checkpoint(&checkpoint).is_err());
        checkpoint.accounts_hash = raw(TERMINAL_ACCOUNTS);
        gate.checkpoint(&checkpoint).unwrap();
        assert!(
            gate.require_natural_close(h::HistoricalShutdownOutcome::Reaped {
                worker_pid: 42,
                forced: true
            })
            .is_err()
        );
        gate.require_natural_close(clean).unwrap();
    }
}
