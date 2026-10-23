//! Test-only native1.2.0 export/fresh-process continuation experiment.
//! No production dispatch, synthetic-genesis acceptance or resume authority.
use super::*;
use bzip2::{write::BzEncoder, Compression};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use solana_runtime::{
    genesis_utils::create_genesis_config_with_leader,
    snapshot_utils::{add_snapshot, serialize_status_cache, SnapshotVersion},
};
use solana_sdk::{signature::Signature, system_program, system_transaction};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{BufWriter, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
    process::Command,
};

const ROOT_ENV: &str = "JETSTREAMER_V1425_PORTABILITY_FIXTURE_ROOT";
const CHILD_ENV: &str = "JETSTREAMER_V1425_PORTABILITY_CHILD";
const CHILD_TEST: &str = "runtime::checkpoint_portability_fixture::fresh_process_restore_child";
const MAX_SELECTED_BYTES: u64 = 512 << 20;
const MAX_SMALL_FILE: u64 = 8 << 20;
const MAX_FIXTURE_PHYSICAL_BYTES: u64 = 10 << 30;

fn fixture_budget(root: &Path) {
    let device = fs::metadata(root).unwrap().dev();
    let mut queue = vec![root.to_path_buf()];
    let mut bytes = 0u64;
    let mut count = 0;
    while let Some(path) = queue.pop() {
        count += 1;
        assert!(count <= 65536, "fixture member bound exceeded");
        let md = fs::symlink_metadata(&path).unwrap();
        assert_eq!(md.dev(), device, "fixture crossed a filesystem");
        assert!(!md.file_type().is_symlink(), "fixture contains an alias");
        bytes = bytes
            .checked_add(md.blocks().checked_mul(512).unwrap())
            .unwrap();
        assert!(
            bytes <= MAX_FIXTURE_PHYSICAL_BYTES,
            "fixture10GiB physical stop"
        );
        if md.is_dir() {
            for entry in fs::read_dir(&path).unwrap() {
                queue.push(entry.unwrap().path());
            }
        } else {
            assert!(md.is_file() && md.nlink() == 1, "unexpected fixture member");
        }
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
struct Member {
    relative_path: String,
    length: u64,
    sha256: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
struct Plan {
    schema: String,
    capped: bool,
    creator_pid: u32,
    test_executable_sha256: Vec<u8>,
    genesis: Member,
    archive: Member,
    members: Vec<Member>,
    staging_directory: String,
    checkpoint: Checkpoint,
    rooted_signature: Vec<u8>,
    roots: Vec<u64>,
    requests: Vec<EntryRequest>,
    responses: Vec<EntryProcessed>,
    terminal_checkpoints: Vec<Checkpoint>,
    duplicate: EntryRequest,
    duplicate_error: String,
}

fn private(path: &Path) {
    let md = fs::symlink_metadata(path).unwrap();
    assert!(path.is_absolute() && path.canonicalize().unwrap() == path);
    assert!(md.is_dir() && md.uid() == unsafe { libc::geteuid() });
    assert_eq!(md.mode() & 0o777, 0o700);
    // This stage is specifically OS-volume-only. Never accept campaign/home
    // scratch via the environment, even when its caller has spare capacity.
    assert!(path.starts_with("/var/lib/jetstreamer-checkpoint-fixtures"));
}

fn measure(root: &Path, path: &Path) -> Member {
    assert_eq!(path.canonicalize().unwrap(), path);
    let md = fs::symlink_metadata(path).unwrap();
    assert!(md.is_file() && md.nlink() == 1);
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .unwrap();
    let mut h = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut length = 0;
    loop {
        let n = file.read(&mut buffer).unwrap();
        if n == 0 {
            break;
        }
        h.input(&buffer[..n]);
        length += n as u64;
    }
    assert_eq!(length, md.len());
    assert_eq!(file.metadata().unwrap().len(), md.len());
    Member {
        relative_path: path.strip_prefix(root).unwrap().to_str().unwrap().into(),
        length,
        sha256: h.result().as_slice().to_vec(),
    }
}

fn checked_member(root: &Path, m: &Member) -> PathBuf {
    let relative = Path::new(&m.relative_path);
    assert!(relative
        .components()
        .all(|p| matches!(p, Component::Normal(_))));
    let path = root.join(relative);
    assert_eq!(measure(root, &path), *m);
    path
}

fn write_new<T: Serialize>(path: &Path, value: &T) {
    let bytes = bincode::serialize(value).unwrap();
    assert!(bytes.len() as u64 <= MAX_SMALL_FILE);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .unwrap();
    file.write_all(&bytes).unwrap();
    file.sync_all().unwrap();
    File::open(path.parent().unwrap())
        .unwrap()
        .sync_all()
        .unwrap();
}

fn tuple(state: &RuntimeState) -> Checkpoint {
    Checkpoint {
        slot: state.bank.slot(),
        bank_hash: state.bank.hash().as_ref().to_vec(),
        accounts_hash: state.bank.get_accounts_hash().as_ref().to_vec(),
        last_blockhash: state.bank.last_blockhash().as_ref().to_vec(),
        capitalization: state.bank.capitalization(),
        transaction_count: state.bank.transaction_count(),
        tick_height: state.bank.tick_height(),
        slot_complete: state.bank.is_complete(),
        writes: Vec::new(),
        next_write_version: state.write_cursor,
    }
}

fn request(state: &RuntimeState, slot: u64, txs: &[Transaction]) -> EntryRequest {
    let start = if slot > state.bank.slot() {
        state.bank.last_blockhash()
    } else {
        state.last_entry_hash
    };
    EntryRequest {
        slot,
        entry_index: if slot > state.bank.slot() {
            0
        } else {
            state.next_entry_index
        },
        num_hashes: 1,
        hash: next_entry_hash(&start, 1, txs).as_ref().to_vec(),
        transactions: txs.iter().map(|t| bincode::serialize(t).unwrap()).collect(),
    }
}

fn tick_to_completion(
    state: &mut RuntimeState,
    slot: u64,
    requests: &mut Vec<EntryRequest>,
    responses: &mut Vec<EntryProcessed>,
) {
    while state.bank.slot() != slot || !state.bank.is_complete() {
        fixture_budget(state._state_dir.path().parent().unwrap());
        let q = request(state, slot, &[]);
        let r = state.process_entry(q.clone()).unwrap();
        requests.push(q);
        responses.push(r);
    }
}

fn native_export(root: &Path, state: &RuntimeState) -> (Member, Vec<Member>) {
    let before = tuple(state);
    assert!(state.bank.is_frozen() && state.bank.parent().is_none());
    assert_eq!(state.tick_hash_count, 0);
    assert_eq!(
        state.write_cursor,
        state.bank.accounts().accounts_db.next_write_version()
    );
    let staging = root.join("native-staging");
    fs::create_dir(&staging).unwrap();
    let snapshots = staging.join("snapshots");
    let accounts = staging.join("accounts");
    fs::create_dir(&snapshots).unwrap();
    fs::create_dir(&accounts).unwrap();
    let storages = state.bank.get_snapshot_storages();
    let selected_bytes: u64 = storages
        .iter()
        .flatten()
        .map(|s| fs::metadata(s.get_path()).unwrap().len())
        .sum();
    assert!(selected_bytes <= MAX_SELECTED_BYTES);
    // Public helper invokes the exact private bank_to_stream(NEWER) serializer.
    // No archive packager, retention helper, cleaning, shell or host tar.
    let bank_file = add_snapshot(&snapshots, &state.bank, &storages, SnapshotVersion::V1_2_0)
        .unwrap()
        .snapshot_file_path;
    File::open(&bank_file).unwrap().sync_all().unwrap();
    let roots = state.bank.src.roots();
    assert_eq!(roots.last(), Some(&state.bank.slot()));
    let status = snapshots.join("status_cache");
    serialize_status_cache(
        state.bank.slot(),
        &state.bank.src.slot_deltas(&roots),
        &status,
    )
    .unwrap();
    File::open(&status).unwrap().sync_all().unwrap();
    let version = staging.join("version");
    let mut version_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&version)
        .unwrap();
    version_file.write_all(b"1.2.0").unwrap();
    version_file.sync_all().unwrap();
    let mut members = vec![
        measure(&staging, &bank_file),
        measure(&staging, &status),
        measure(&staging, &version),
    ];
    for s in storages.iter().flatten() {
        fixture_budget(root);
        s.flush().unwrap();
        let source = s.get_path();
        let destination = accounts.join(source.file_name().unwrap());
        assert!(!destination.exists());
        // Disposable selected AppendVecs only; never hard-link live state.
        fs::copy(&source, &destination).unwrap();
        File::open(&destination).unwrap().sync_all().unwrap();
        members.push(measure(&staging, &destination));
    }
    members.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    assert!(members
        .windows(2)
        .all(|w| w[0].relative_path != w[1].relative_path));
    let archive = root.join(format!(
        "snapshot-{}-{}.tar.bz2",
        state.bank.slot(),
        state.bank.get_accounts_hash()
    ));
    let output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&archive)
        .unwrap();
    let encoder = BzEncoder::new(BufWriter::new(output), Compression::Fastest);
    let mut tar = tar::Builder::new(encoder);
    for member in &members {
        let path = checked_member(&staging, member);
        tar.append_path_with_name(path, &member.relative_path)
            .unwrap();
    }
    let mut output = tar.into_inner().unwrap().finish().unwrap();
    output.flush().unwrap();
    output.get_ref().sync_all().unwrap();
    drop(output);
    File::open(root).unwrap().sync_all().unwrap();
    assert_eq!(before, tuple(state));
    fixture_budget(root);
    assert_eq!(
        state.write_cursor,
        state.bank.accounts().accounts_db.next_write_version()
    );
    (measure(root, &archive), members)
}

#[test]
#[ignore]
fn native_v12_fresh_process_raw_output_equivalence() {
    run_fixture(false);
}

#[test]
#[ignore]
fn native_export_dispatch_fresh_process_raw_output_equivalence() {
    run_fixture(true);
}

fn run_fixture(via_dispatch: bool) {
    assert!(std::env::var_os(CHILD_ENV).is_none());
    let base = PathBuf::from(
        std::env::var_os(ROOT_ENV).expect("requires separately admitted OS-only fixture root"),
    );
    private(&base);
    assert_eq!(
        fs::read_dir(&base).unwrap().count(),
        0,
        "fixture root must be empty"
    );
    let d = tempfile::Builder::new()
        .prefix("native-v12-")
        .tempdir_in(&base)
        .unwrap();
    // Preserve failed experiment evidence too. Only the exact admitted fixture
    // directory may be cleaned by its caller after review.
    let retained_root = d.into_path();
    let root = retained_root.as_path();
    let state_dir = snapshot::private_state_dir(root.to_str()).unwrap();
    let mut genesis =
        create_genesis_config_with_leader(1_000_000, &Pubkey::new_from_array([7; 32]), 500_000);
    genesis.genesis_config.ticks_per_slot = 2;
    genesis.genesis_config.poh_config.hashes_per_tick = None;
    genesis.genesis_config.cluster_type = ClusterType::MainnetBeta;
    genesis.genesis_config.native_instruction_processors = vec![
        ("solana_config_program".into(), solana_config_program::id()),
        ("solana_stake_program".into(), solana_stake_program::id()),
        ("solana_system_program".into(), system_program::id()),
        ("solana_vote_program".into(), solana_vote_program::id()),
    ];
    let ledger = root.join("genesis");
    fs::create_dir(&ledger).unwrap();
    genesis.genesis_config.write(&ledger).unwrap();
    let bank = Bank::new_with_paths(
        &genesis.genesis_config,
        snapshot::private_account_paths(&state_dir).unwrap(),
        &[],
        None,
        Some(&mainnet_additional_builtins()),
        HashSet::new(),
    );
    let mut state = RuntimeState::from_test_bank(bank, true, state_dir);
    tick_to_completion(&mut state, 0, &mut Vec::new(), &mut Vec::new());
    state.freeze_checkpoint(0).unwrap();
    let rooted_tx = system_transaction::transfer(
        &genesis.mint_keypair,
        &Pubkey::new_from_array([41; 32]),
        123,
        state.bank.last_blockhash(),
    );
    let rooted = state
        .process_entry(request(&state, 1, &[rooted_tx.clone()]))
        .unwrap();
    assert_eq!(rooted.outcomes[0].error, None);
    tick_to_completion(&mut state, 1, &mut Vec::new(), &mut Vec::new());
    state.freeze_checkpoint(1).unwrap();
    assert_eq!(
        state.bank.get_signature_status(&rooted_tx.signatures[0]),
        Some(Ok(()))
    );
    let checkpoint = tuple(&state);
    let roots = state.bank.src.roots();
    let (archive, members, staging_directory) = if via_dispatch {
        let selected_bytes: u64 = state
            .bank
            .get_snapshot_storages()
            .iter()
            .flatten()
            .map(|s| fs::metadata(s.get_path()).unwrap().len())
            .sum();
        assert!(selected_bytes <= MAX_SELECTED_BYTES);
        // cfg(test) injection only: exercise the unchanged real request dispatcher,
        // without adding a synthetic Initialize selector to the production worker.
        let mut worker = crate::Worker {
            hello_complete: false,
            state: Some(state),
        };
        use jetstreamer_historical_protocol::{
            Request, RequestBody, ResponseBody, PROTOCOL_VERSION,
        };
        let (hello, stop) = worker.handle(Request {
            id: 1,
            body: RequestBody::Hello {
                protocol_version: PROTOCOL_VERSION,
            },
        });
        assert!(!stop);
        assert!(matches!(hello.body, ResponseBody::Handshake(_)));
        let (frozen, stop) = worker.handle(Request {
            id: 2,
            body: RequestBody::FreezeCheckpoint { slot: 1 },
        });
        assert!(!stop);
        let checkpoint = match frozen.body {
            ResponseBody::Checkpoint(c) => c,
            other => panic!("unexpected freeze response: {:?}", other),
        };
        let (response, stop) = worker.handle(Request {
            id: 3,
            body: RequestBody::ExportSnapshot {
                slot: 1,
                output_directory: root.to_str().unwrap().into(),
                expected_accounts_hash: checkpoint.accounts_hash,
            },
        });
        assert!(!stop);
        let exported = match response.body {
            ResponseBody::SnapshotExported(s) => s,
            other => panic!("unexpected export response: {:?}", other),
        };
        state = worker.state.take().unwrap();
        let archive = measure(root, Path::new(&exported.archive_path));
        assert_eq!(archive.length, exported.archive_size);
        assert_eq!(archive.sha256, exported.archive_sha256);
        let stages: Vec<_> = fs::read_dir(root)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .starts_with("jetstreamer-native-export-")
            })
            .collect();
        assert_eq!(stages.len(), 1);
        let staging = &stages[0];
        private(staging);
        let mut paths = vec![
            staging.join("snapshots/1/1"),
            staging.join("snapshots/status_cache"),
            staging.join("version"),
            staging.join("export-manifest.bin"),
        ];
        paths.extend(
            fs::read_dir(staging.join("accounts"))
                .unwrap()
                .map(|e| e.unwrap().path()),
        );
        let members = paths.iter().map(|p| measure(staging, p)).collect();
        (
            archive,
            members,
            staging.file_name().unwrap().to_str().unwrap().to_string(),
        )
    } else {
        let (archive, members) = native_export(root, &state);
        (archive, members, "native-staging".to_string())
    };
    assert_eq!(tuple(&state), checkpoint);
    let mut requests = Vec::new();
    let mut responses = Vec::new();
    let mut terminals = Vec::new();
    // Slot4 deliberately skips parent slot3; every required tick is explicit.
    for slot in &[2u64, 4] {
        for amount in &[321u64, 10_000_000] {
            let tx = system_transaction::transfer(
                &genesis.mint_keypair,
                &Pubkey::new_from_array([42; 32]),
                *amount,
                state.bank.last_blockhash(),
            );
            let q = request(&state, *slot, &[tx]);
            let r = state.process_entry(q.clone()).unwrap();
            fixture_budget(root);
            assert_eq!(r.outcomes[0].error.is_some(), *amount == 10_000_000);
            requests.push(q);
            responses.push(r);
        }
        tick_to_completion(&mut state, *slot, &mut requests, &mut responses);
        let checkpoint = state.freeze_checkpoint(*slot).unwrap();
        terminals.push(checkpoint);
    }
    let duplicate = request(&state, 5, &[rooted_tx.clone()]);
    let duplicate_error = state.process_entry(duplicate.clone()).unwrap_err();
    assert_eq!(
        duplicate_error,
        format!(
            "entry fee collection failed for transaction 0: {:?}",
            Err::<(), _>(TransactionError::DuplicateSignature),
        )
    );
    let plan = Plan {
        schema: "test-only-v1425-native-v12-portability-v2".into(),
        capped: cfg!(feature = "capped-shrink-candidate"),
        creator_pid: std::process::id(),
        test_executable_sha256: {
            let exe = std::env::current_exe().unwrap().canonicalize().unwrap();
            measure(exe.parent().unwrap(), &exe).sha256
        },
        genesis: measure(root, &ledger.join("genesis.bin")),
        archive,
        members,
        staging_directory,
        checkpoint,
        rooted_signature: rooted_tx.signatures[0].as_ref().to_vec(),
        roots,
        requests,
        responses,
        terminal_checkpoints: terminals,
        duplicate,
        duplicate_error,
    };
    write_new(&root.join("plan.bin"), &plan);
    let result = Command::new(std::env::current_exe().unwrap())
        .args(&[
            "--ignored",
            "--exact",
            CHILD_TEST,
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ENV, root)
        .env(ROOT_ENV, &base)
        .env("JETSTREAMER_HISTORICAL_POH_THREADS", "2")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "fresh child failed: {}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(root.join("child-success.bin").is_file());
    // Retain the disposable evidence tree for review; caller owns its exact cleanup.
    println!(
        "native-v12 portability fixture evidence: {}",
        root.display()
    );
}

#[test]
#[ignore]
fn fresh_process_restore_child() {
    let base = PathBuf::from(std::env::var_os(ROOT_ENV).expect("fixture root required"));
    private(&base);
    let root = PathBuf::from(std::env::var_os(CHILD_ENV).expect("child fixture required"));
    private(&root);
    assert_eq!(root.parent(), Some(base.as_path()));
    let plan_path = root.join("plan.bin");
    assert!(fs::metadata(&plan_path).unwrap().len() <= MAX_SMALL_FILE);
    let plan: Plan = bincode::deserialize(&fs::read(plan_path).unwrap()).unwrap();
    assert_eq!(plan.schema, "test-only-v1425-native-v12-portability-v2");
    assert_eq!(plan.capped, cfg!(feature = "capped-shrink-candidate"));
    assert_ne!(plan.creator_pid, std::process::id());
    let exe = std::env::current_exe().unwrap().canonicalize().unwrap();
    assert_eq!(
        measure(exe.parent().unwrap(), &exe).sha256,
        plan.test_executable_sha256
    );
    checked_member(&root, &plan.genesis);
    let archive = checked_member(&root, &plan.archive);
    assert!(
        Path::new(&plan.staging_directory).components().count() == 1
            && matches!(
                Path::new(&plan.staging_directory).components().next(),
                Some(Component::Normal(_))
            )
    );
    let staging = root.join(&plan.staging_directory);
    for member in &plan.members {
        checked_member(&staging, member);
    }
    let state_dir = snapshot::private_state_dir(root.to_str()).unwrap();
    // Test-only synthetic genesis is never accepted by RuntimeState::initialize.
    let genesis = snapshot::load_genesis(&root.join("genesis"), &state_dir).unwrap();
    let loaded = snapshot::load_archive(
        &archive,
        &state_dir,
        &genesis,
        &mainnet_additional_builtins(),
    )
    .unwrap();
    fixture_budget(&root);
    let mut state = RuntimeState::from_test_bank(loaded.bank, true, state_dir);
    assert_eq!(tuple(&state), plan.checkpoint);
    assert_eq!(state.bank.src.roots(), plan.roots);
    assert_eq!(
        state
            .bank
            .get_signature_status(&Signature::new(&plan.rooted_signature)),
        Some(Ok(()))
    );
    assert_eq!(state.tick_hash_count, 0);
    assert_eq!(state.next_entry_index, 0);
    assert_eq!(
        state.last_entry_hash.as_ref(),
        plan.checkpoint.last_blockhash.as_slice()
    );
    assert_eq!(plan.requests.len(), plan.responses.len());
    assert_eq!(plan.requests[0].slot, plan.checkpoint.slot + 1);
    assert_eq!(plan.requests[0].entry_index, 0);
    let mut terminal_index = 0;
    for (q, expected) in plan.requests.iter().zip(&plan.responses) {
        let actual = state.process_entry(q.clone()).unwrap();
        fixture_budget(&root);
        assert_eq!(&actual, expected); // Includes every raw write and signature attribution.
        assert_eq!(state.last_entry_hash.as_ref(), q.hash.as_slice());
        if actual.slot_complete {
            assert_eq!(
                state.freeze_checkpoint(q.slot).unwrap(),
                plan.terminal_checkpoints[terminal_index]
            );
            terminal_index += 1;
        }
    }
    assert_eq!(terminal_index, plan.terminal_checkpoints.len());
    assert_eq!(
        state.process_entry(plan.duplicate).unwrap_err(),
        plan.duplicate_error
    );
    write_new(
        &root.join("child-success.bin"),
        &(
            "native-v12-fresh-process-equivalence-test-only",
            plan.creator_pid,
            std::process::id(),
            plan.capped,
            measure(&root, &root.join("plan.bin")).sha256,
            plan.test_executable_sha256,
            plan.archive,
            false, // production resume authority
        ),
    );
}
