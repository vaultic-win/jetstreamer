//! Opt-in actual-worker round trip of the retained epoch-265 mainnet bootstrap.
//! Requires separate resource admission; no entries, archives, or R2 publication.
use jetstreamer_historical_protocol::{
    read_frame, write_frame, BackendQualification, Checkpoint, InitialState, Request, RequestBody,
    Response, ResponseBody, MAINNET_GENESIS_HASH, PROTOCOL_VERSION,
};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};

const SLOT: u64 = 114_479_281;
const WORKER_SHA: &str = "8275e240f40a8ce6cbba95bf16266df4e2cd2c8fb398c4ae3a20b02e707966c3";
const SNAPSHOT_SHA: &str = "04eb59e2dbbc2b0d4f1535741fa9d56794c32ad18e14c98df4fa76a5ae397641";
const ACCOUNTS_HASH: &str = "Jo2p1i6wNNn71fwwkyoA6shEtYtovbqzVc6p2W16FzW";

fn digest(path: &Path, immutable: bool) -> (u64, Vec<u8>) {
    assert!(path.is_absolute());
    assert_eq!(fs::canonicalize(path).unwrap(), path);
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .unwrap();
    let before = file.metadata().unwrap();
    assert!(before.is_file());
    assert_eq!(before.nlink(), 1);
    if immutable {
        assert_eq!(before.uid(), 0);
        assert_eq!(before.mode() & 0o222, 0);
    }
    let mut h = Sha256::new();
    let mut buffer = [0u8; 128 * 1024];
    let mut size = 0u64;
    loop {
        let n = file.read(&mut buffer).unwrap();
        if n == 0 {
            break;
        }
        h.input(&buffer[..n]);
        size += n as u64;
    }
    let after = fs::symlink_metadata(path).unwrap();
    assert_eq!(
        (
            before.dev(),
            before.ino(),
            before.len(),
            before.mtime(),
            before.mtime_nsec()
        ),
        (
            after.dev(),
            after.ino(),
            after.len(),
            after.mtime(),
            after.mtime_nsec()
        )
    );
    assert_eq!(size, before.len());
    (size, h.result().to_vec())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
fn environment_path(name: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(name).expect(name))
}

struct Session {
    child: Child,
    next_id: u64,
    closed: bool,
}
impl Session {
    fn start(worker: &Path, ledger: &Path, snapshot: &Path, scratch: &Path) -> Self {
        assert_eq!(hex(&digest(worker, true).1), WORKER_SHA);
        let child = Command::new(worker)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut session = Self {
            child,
            next_id: 1,
            closed: false,
        };
        match session.exchange(RequestBody::Hello {
            protocol_version: PROTOCOL_VERSION,
        }) {
            ResponseBody::Handshake(h) => {
                assert_eq!(h.protocol_version, PROTOCOL_VERSION);
                assert_eq!(h.backend_id, "solana-v1.7.15");
                assert_eq!(h.qualification, BackendQualification::Candidate);
                assert_eq!(h.solana_commit, "4892eb4e1ad278d5249b6cda8983f88effb3e98b");
                assert_eq!(h.required_genesis_hash, MAINNET_GENESIS_HASH);
            }
            other => panic!("unexpected handshake: {:?}", other),
        }
        match session.exchange(RequestBody::Initialize {
            ledger_path: ledger.to_str().unwrap().into(),
            initial_state: InitialState::SnapshotArchive {
                archive_path: snapshot.to_str().unwrap().into(),
            },
            scratch_root: Some(scratch.to_str().unwrap().into()),
        }) {
            ResponseBody::Initialized(i) => {
                assert_eq!(i.slot, SLOT);
                assert_eq!(i.genesis_hash, MAINNET_GENESIS_HASH);
            }
            other => panic!("initialization failed: {:?}", other),
        }
        session
    }
    fn exchange(&mut self, body: RequestBody) -> ResponseBody {
        let id = self.next_id;
        self.next_id += 1;
        write_frame(self.child.stdin.as_mut().unwrap(), &Request { id, body }).unwrap();
        let response: Response = read_frame(self.child.stdout.as_mut().unwrap())
            .unwrap()
            .expect("worker EOF");
        assert_eq!(response.request_id, id);
        response.body
    }
    fn checkpoint(&mut self) -> Checkpoint {
        match self.exchange(RequestBody::FreezeCheckpoint { slot: SLOT }) {
            ResponseBody::Checkpoint(c) => {
                assert_eq!(c.slot, SLOT);
                assert!(c.slot_complete && c.writes.is_empty());
                assert_eq!(bs58::encode(&c.accounts_hash).into_string(), ACCOUNTS_HASH);
                c
            }
            other => panic!("checkpoint failed: {:?}", other),
        }
    }
    fn shutdown(&mut self) {
        assert_eq!(
            self.exchange(RequestBody::Shutdown),
            ResponseBody::ShuttingDown
        );
        self.child.stdin.take();
        assert!(self.child.wait().unwrap().success());
        self.closed = true;
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        if !self.closed {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[test]
#[ignore]
fn epoch265_actual_worker_export_and_fresh_restore() {
    let worker = environment_path("JETSTREAMER_CHECKPOINT_EXPORT_WORKER");
    let snapshot = environment_path("JETSTREAMER_SNAPSHOT_114479281");
    let ledger = environment_path("JETSTREAMER_MAINNET_LEDGER");
    let root = environment_path("JETSTREAMER_CHECKPOINT_EXPORT_PROBE_ROOT");
    assert_eq!(fs::canonicalize(&root).unwrap(), root);
    let metadata = fs::symlink_metadata(&root).unwrap();
    assert!(metadata.is_dir());
    assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
    assert_eq!(metadata.mode() & 0o077, 0);
    assert_eq!(
        fs::read_dir(&root).unwrap().count(),
        0,
        "use a new empty attempt directory"
    );
    let (size, sha) = digest(&snapshot, true);
    assert_eq!(size, 16_483_458_670);
    assert_eq!(hex(&sha), SNAPSHOT_SHA);
    let exports = root.join("exports");
    let source = root.join("source");
    let restore = root.join("restore");
    for directory in &[&exports, &source, &restore] {
        fs::DirBuilder::new().mode(0o700).create(directory).unwrap();
    }
    let mut first = Session::start(&worker, &ledger, &snapshot, &source);
    let first_pid = first.child.id();
    let before = first.checkpoint();
    let exported = match first.exchange(RequestBody::ExportSnapshot {
        slot: SLOT,
        output_directory: exports.to_str().unwrap().into(),
        expected_accounts_hash: before.accounts_hash.clone(),
    }) {
        ResponseBody::SnapshotExported(e) => e,
        other => panic!("export failed: {:?}", other),
    };
    assert_eq!(exported.slot, SLOT);
    assert_eq!(exported.accounts_hash, before.accounts_hash);
    let archive = exports.join(format!("snapshot-{}-{}.tar.bz2", SLOT, ACCOUNTS_HASH));
    assert_eq!(Path::new(&exported.archive_path), archive);
    assert_eq!(
        digest(&archive, false),
        (exported.archive_size, exported.archive_sha256.clone())
    );
    assert_eq!(
        first.checkpoint(),
        before,
        "export changed the source checkpoint"
    );
    first.shutdown();
    drop(first);
    assert_eq!(
        fs::read_dir(&source).unwrap().count(),
        0,
        "original worker scratch survived shutdown"
    );

    let mut second = Session::start(&worker, &ledger, &archive, &restore);
    let second_pid = second.child.id();
    assert_ne!(first_pid, second_pid);
    let after = second.checkpoint();
    assert_eq!(
        before, after,
        "fresh-process native mainnet restore differs"
    );
    second.shutdown();
    drop(second);
    assert_eq!(fs::read_dir(&restore).unwrap().count(), 0);
    assert_eq!(
        digest(&archive, false),
        (exported.archive_size, exported.archive_sha256.clone())
    );
    assert_eq!(hex(&digest(&worker, true).1), WORKER_SHA);
    let evidence = bincode::serialize(&(
        "horizon-v1715-epoch265-native-export-restore-v1",
        WORKER_SHA,
        SNAPSHOT_SHA,
        first_pid,
        second_pid,
        exported,
        before,
        after,
    ))
    .unwrap();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(root.join("native-roundtrip.bin"))
        .unwrap();
    file.write_all(&evidence).unwrap();
    file.sync_all().unwrap();
    File::open(&root).unwrap().sync_all().unwrap();
    println!(
        "mainnet export/restore complete: slot={} evidence_sha256={}",
        SLOT,
        hex(Sha256::digest(&evidence).as_slice())
    );
}
