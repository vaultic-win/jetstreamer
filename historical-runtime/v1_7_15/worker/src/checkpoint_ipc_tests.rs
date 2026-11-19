// Included only in runtime::tests. This synthetic worker is never a production
// backend and cannot claim mainnet initialization or registry qualification.
#[test]
#[ignore]
fn checkpoint_export_live_ipc_fixture() {
    use jetstreamer_historical_protocol::{
        InitialState, Initialized, InitializedSource, Request, RequestBody, Response, ResponseBody,
    };
    use std::{fs, io, os::unix::io::FromRawFd, path::PathBuf};
    let fd: i32 = std::env::var("JETSTREAMER_CHECKPOINT_FIXTURE_OUTPUT_FD")
        .expect("only the isolated fixture launcher may select this test")
        .parse()
        .unwrap();
    assert!(fd >= 3);
    let genesis_path =
        PathBuf::from(std::env::var_os("JETSTREAMER_CHECKPOINT_FIXTURE_GENESIS").unwrap());
    let bytes = fs::read(&genesis_path).unwrap();
    assert!(bytes.len() <= 10 * 1024 * 1024);
    let genesis: GenesisConfig = bincode::deserialize(&bytes).unwrap();
    assert_ne!(
        genesis.hash().to_string(),
        jetstreamer_historical_protocol::MAINNET_GENESIS_HASH
    );
    let mut input = io::stdin();
    // Test-harness output stays on stderr. Only framed production protocol
    // responses use the original parent pipe inherited from the launcher.
    let mut output = unsafe { fs::File::from_raw_fd(fd) };
    let mut worker = crate::Worker::new();
    while let Some(request) =
        jetstreamer_historical_protocol::read_frame::<Request, _>(&mut input).unwrap()
    {
        let id = request.id;
        match request.body {
            RequestBody::Hello { protocol_version } => {
                assert_eq!(
                    protocol_version,
                    jetstreamer_historical_protocol::PROTOCOL_VERSION
                );
                worker.hello_complete = true;
                let mut hello = crate::handshake();
                hello.backend_id = "synthetic-v1.7.15-checkpoint-ipc-fixture".into();
                hello.required_genesis_hash = genesis.hash().to_string();
                crate::write_worker_response(
                    &mut output,
                    Response {
                        request_id: id,
                        body: ResponseBody::Handshake(hello),
                    },
                )
                .unwrap();
            }
            RequestBody::Initialize {
                initial_state,
                scratch_root,
                ..
            } => {
                assert!(worker.hello_complete && worker.state.is_none());
                let archive = match initial_state {
                    InitialState::SnapshotArchive { archive_path } => PathBuf::from(archive_path),
                    _ => panic!("fixture only supports explicit snapshot initialization"),
                };
                let directory = snapshot::private_state_dir(scratch_root.as_deref()).unwrap();
                let loaded = snapshot::load_archive(
                    &archive,
                    &directory,
                    &genesis,
                    &Builtins {
                        genesis_builtins: Vec::new(),
                        feature_builtins: Vec::new(),
                    },
                )
                .unwrap();
                assert!(loaded.bank.verify_snapshot_bank(true, false));
                let initialized = Initialized {
                    genesis_hash: genesis.hash().to_string(),
                    source: InitializedSource::SnapshotArchive {
                        archive_path: archive.to_str().unwrap().into(),
                        expected_accounts_hash: loaded.bank.get_accounts_hash().as_ref().to_vec(),
                    },
                    slot: loaded.bank.slot(),
                    last_blockhash: loaded.bank.last_blockhash().as_ref().to_vec(),
                    ticks_per_slot: genesis.ticks_per_slot,
                    next_write_version: loaded.bank.accounts().accounts_db.next_write_version(),
                };
                worker.state = Some(RuntimeState::from_test_bank(loaded.bank, false, directory));
                crate::write_worker_response(
                    &mut output,
                    Response {
                        request_id: id,
                        body: ResponseBody::Initialized(initialized),
                    },
                )
                .unwrap();
            }
            RequestBody::ProcessEntries(entries) => {
                assert!(!worker
                    .process_entry_batch(id, entries, &mut output)
                    .unwrap());
            }
            body => {
                let (response, stop) = worker.handle(Request { id, body });
                crate::write_worker_response(&mut output, response).unwrap();
                if stop {
                    drop(worker);
                    return;
                }
            }
        }
    }
    panic!("fixture parent disconnected without ordered shutdown");
}
