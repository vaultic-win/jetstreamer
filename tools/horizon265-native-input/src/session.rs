use anyhow::{Context, Result, bail, ensure};
use jetstreamer_historical_protocol_current::{
    BackendQualification, Checkpoint, Handshake, InitialState, Initialized, InitializedSource,
    MAINNET_GENESIS_HASH, PROTOCOL_VERSION, Request, RequestBody, Response, ResponseBody,
    read_frame, write_frame,
};
use profile::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::Path,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
const LOG_LIMIT: u64 = 8 << 20;

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn identity(path: &Path) -> Result<Value> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.is_absolute()
            && path.canonicalize()? == path
            && m.is_file()
            && m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o222 == 0
            && m.nlink() == 1,
        "input custody changed: {}",
        path.display()
    );
    Ok(
        json!({"device":m.dev(),"inode":m.ino(),"bytes":m.len(),"uid":m.uid(),"gid":m.gid(),"mode":m.mode(),"nlink":m.nlink(),"mtime":m.mtime(),"mtime_nsec":m.mtime_nsec(),"ctime":m.ctime(),"ctime_nsec":m.ctime_nsec()}),
    )
}
fn read_small(path: &Path, sha: &str, limit: u64) -> Result<Vec<u8>> {
    let before = identity(path)?;
    ensure!(
        before["bytes"].as_u64().context("length")? <= limit,
        "input too large"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    ensure!(
        f.metadata()?.ino() == before["inode"].as_u64().unwrap(),
        "open race"
    );
    let mut bytes = Vec::new();
    (&mut f).take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit && digest(&bytes) == sha && identity(path)? == before,
        "input bytes changed"
    );
    Ok(bytes)
}
fn inputs() -> Result<Value> {
    let p: Value = serde_json::from_slice(&read_small(Path::new(PACKET), PACKET_SHA, 2 << 20)?)?;
    ensure!(
        p["schema"] == INPUT_SCHEMA && p["epoch"] == EPOCH && profile::measurement_verified(&p),
        "foreign input packet"
    );
    profile::validate_extra(&p)?;
    let files = p["files"].as_array().context("packet files")?;
    for (path, sha, bytes) in [
        (WORKER, WORKER_SHA, WORKER_BYTES),
        (SNAPSHOT, SNAPSHOT_SHA, SNAPSHOT_SIZE),
        (GENESIS, GENESIS_SHA, 20_144),
    ] {
        let found: Vec<_> = files
            .iter()
            .filter(|v| v["path"] == path && v["sha256"] == sha)
            .collect();
        let actual = identity(Path::new(path))?;
        ensure!(
            found.len() == 1 && found[0]["identity"] == actual && actual["bytes"] == bytes,
            "sealed packet input changed: {path}"
        );
    }
    // Snapshot bytes were already verified by the sealed packet. Identity checks
    // retain that evidence; a new 16GB hash is not hidden inside the startup lease.
    read_small(Path::new(WORKER), WORKER_SHA, WORKER_BYTES)?;
    Ok(p)
}
fn handshake(h: &Handshake) -> Result<()> {
    ensure!(
        h.protocol_version == PROTOCOL_VERSION
            && h.backend_id == BACKEND
            && h.qualification == BackendQualification::Candidate
            && h.solana_commit == SOLANA_COMMIT
            && h.required_genesis_hash == MAINNET_GENESIS_HASH,
        "foreign worker handshake"
    );
    Ok(())
}
fn initialized(i: &Initialized) -> Result<()> {
    ensure!(
        i.slot == SLOT
            && i.genesis_hash == MAINNET_GENESIS_HASH
            && i.last_blockhash.len() == 32
            && i.ticks_per_slot > 0,
        "initial state differs"
    );
    match &i.source {
        InitializedSource::SnapshotArchive {
            archive_path,
            expected_accounts_hash,
        } => ensure!(
            archive_path == SNAPSHOT
                && bs58::encode(expected_accounts_hash).into_string() == ACCOUNTS_HASH,
            "initialized snapshot differs"
        ),
        _ => bail!("worker initialized from genesis"),
    }
    Ok(())
}
fn checkpoint(c: &Checkpoint, initial_write_version: u64) -> Result<()> {
    ensure!(
        c.slot == SLOT
            && c.slot_complete
            && c.writes.is_empty()
            && c.next_write_version == initial_write_version
            && c.accounts_hash.len() == 32
            && bs58::encode(&c.accounts_hash).into_string() == ACCOUNTS_HASH
            && c.bank_hash.len() == 32
            && c.last_blockhash.len() == 32,
        "canonical checkpoint differs"
    );
    Ok(())
}
fn output(path: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?)
}
fn save(name: &str, value: &Value) -> Result<()> {
    let root = Path::new(ROOT);
    let mut f = output(&root.join(name))?;
    serde_json::to_writer_pretty(&mut f, value)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    File::open(root)?.sync_all()?;
    Ok(())
}
fn private_dir(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == path
            && m.is_dir()
            && m.uid() == 1000
            && m.gid() == 1000
            && m.mode() & 0o777 == 0o700,
        "private directory differs"
    );
    Ok(())
}
fn pristine() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 1000,
        "harness must run as ubuntu"
    );
    private_dir(Path::new(ROOT))?;
    ensure!(
        fs::read_dir(ROOT)?.next().is_none(),
        "use a fresh empty root"
    );
    Ok(())
}

/// Poll-bounded pipe I/O prevents a worker from holding a read/write forever.
struct Pipe<T> {
    inner: T,
    end: Instant,
    log_failed: Arc<AtomicBool>,
}
impl<T: AsRawFd> Pipe<T> {
    fn new(inner: T, end: Instant, log_failed: Arc<AtomicBool>) -> Result<Self> {
        let fd = inner.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        ensure!(
            flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == 0,
            "nonblocking pipe setup failed"
        );
        Ok(Self {
            inner,
            end,
            log_failed,
        })
    }
    fn ready(&self, events: i16) -> io::Result<()> {
        loop {
            if self.log_failed.load(Ordering::Acquire) {
                return Err(io::Error::other("worker stderr exceeded bound or failed"));
            }
            if Instant::now() >= self.end {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "native deadline"));
            }
            let mut p = libc::pollfd {
                fd: self.inner.as_raw_fd(),
                events,
                revents: 0,
            };
            let rc = unsafe { libc::poll(&mut p, 1, 100) };
            if rc > 0 {
                return Ok(());
            }
            if rc < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                return Err(io::Error::last_os_error());
            }
        }
    }
}
impl<T: Read + AsRawFd> Read for Pipe<T> {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        loop {
            self.ready(libc::POLLIN)?;
            match self.inner.read(b) {
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                r => return r,
            }
        }
    }
}
impl<T: Write + AsRawFd> Write for Pipe<T> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        loop {
            self.ready(libc::POLLOUT)?;
            match self.inner.write(b) {
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                r => return r,
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
struct Session {
    child: Child,
    input: Option<Pipe<std::process::ChildStdin>>,
    out: Pipe<std::process::ChildStdout>,
    logger: Option<JoinHandle<Result<u64>>>,
    log_failed: Arc<AtomicBool>,
    next_id: u64,
    end: Instant,
    reaped: bool,
}
impl Session {
    fn start(end: Instant) -> Result<Self> {
        let stderr_file = output(&Path::new(ROOT).join("worker.stderr"))?;
        let mut child = Command::new(WORKER)
            .env_clear()
            .env("RUST_LOG", "warn")
            .env("RUST_MIN_STACK", "134217728")
            .env("SOLANA_RAYON_THREADS", "8")
            .env("RAYON_NUM_THREADS", "8")
            .env("JETSTREAMER_HISTORICAL_POH_THREADS", "2")
            .env("TMPDIR", format!("{ROOT}/tmp"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let failed = Arc::new(AtomicBool::new(false));
        let pipes = (|| -> Result<_> {
            Ok((
                Pipe::new(child.stdin.take().context("stdin")?, end, failed.clone())?,
                Pipe::new(child.stdout.take().context("stdout")?, end, failed.clone())?,
            ))
        })();
        let (input, out) = match pipes {
            Ok(v) => v,
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e);
            }
        };
        let stderr = child.stderr.take().context("stderr")?;
        let mut stderr = match Pipe::new(stderr, end, Arc::new(AtomicBool::new(false))) {
            Ok(pipe) => pipe,
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e);
            }
        };
        let signal = failed.clone();
        let logger = thread::spawn(move || {
            let result = (|| -> Result<u64> {
                let mut file = stderr_file;
                let mut count = 0u64;
                let mut b = [0; 8192];
                loop {
                    let n = stderr.read(&mut b)?;
                    if n == 0 {
                        break;
                    }
                    let keep = n.min(LOG_LIMIT.saturating_sub(count) as usize);
                    file.write_all(&b[..keep])?;
                    count = count.saturating_add(n as u64);
                    if count > LOG_LIMIT {
                        signal.store(true, Ordering::Release);
                    }
                }
                file.sync_all()?;
                ensure!(count <= LOG_LIMIT, "stderr bound exceeded");
                Ok(count)
            })();
            if result.is_err() {
                signal.store(true, Ordering::Release);
            }
            result
        });
        Ok(Self {
            child,
            input: Some(input),
            out,
            logger: Some(logger),
            log_failed: failed,
            next_id: 1,
            end,
            reaped: false,
        })
    }
    fn exchange(&mut self, body: RequestBody) -> Result<ResponseBody> {
        // Closed request set makes accidental entry replay/export impossible here.
        ensure!(
            matches!(
                &body,
                RequestBody::Hello { .. }
                    | RequestBody::Initialize { .. }
                    | RequestBody::FreezeCheckpoint { .. }
                    | RequestBody::Shutdown
            ),
            "request outside cold-input scope"
        );
        let id = self.next_id;
        self.next_id += 1;
        write_frame(
            self.input.as_mut().context("closed stdin")?,
            &Request { id, body },
        )?;
        let r: Response = read_frame(&mut self.out)?.context("premature worker EOF")?;
        ensure!(r.request_id == id, "worker response ID differs");
        Ok(r.body)
    }
    fn shutdown(&mut self) -> Result<u64> {
        ensure!(
            self.exchange(RequestBody::Shutdown)? == ResponseBody::ShuttingDown,
            "shutdown not acknowledged"
        );
        self.input.take();
        loop {
            if let Some(status) = self.child.try_wait()? {
                self.reaped = true;
                ensure!(status.success(), "worker exit failure");
                break;
            }
            ensure!(
                Instant::now() < self.end && !self.log_failed.load(Ordering::Acquire),
                "shutdown deadline/log limit"
            );
            thread::sleep(Duration::from_millis(50));
        }
        self.logger
            .take()
            .context("logger")?
            .join()
            .map_err(|_| anyhow::anyhow!("logger panic"))?
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if let Some(logger) = self.logger.take() {
            let _ = logger.join();
        }
    }
}
/// Additional historical checks run before the next worker request.
trait RuntimeChecks {
    const DEADLINE_SECS: u64 = 2700;
    fn match_original(_: &Value, _: &Initialized, _: &Checkpoint) -> Result<()> {
        Ok(())
    }
    fn fingerprint(_: &Handshake) -> Result<()> {
        Ok(())
    }
    fn initialized(_: &Initialized) -> Result<()> {
        Ok(())
    }
    fn frozen(_: &Initialized, _: &Checkpoint) -> Result<()> {
        Ok(())
    }
}
fn run_with<C: RuntimeChecks>() -> Result<()> {
    ensure!(
        std::env::args().len() == 1,
        "no runtime override arguments accepted"
    );
    pristine()?;
    let start = Instant::now();
    let end = start + Duration::from_secs(C::DEADLINE_SECS);
    // No worker spawn, input hash, ledger copy or snapshot work before this gate.
    let gate = gate::admit().map_err(|e| anyhow::anyhow!("first guard gate: {e}"))?;
    let packet = inputs()?;
    for name in ["ledger", "scratch", "tmp"] {
        let path = Path::new(ROOT).join(name);
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    }
    let genesis = read_small(Path::new(GENESIS), GENESIS_SHA, 20_144)?;
    let mut f = output(&Path::new(ROOT).join("ledger/genesis.tar.bz2"))?;
    f.write_all(&genesis)?;
    f.sync_all()?;
    let mut session = Session::start(end)?;
    let pid = session.child.id();
    let h = match session.exchange(RequestBody::Hello {
        protocol_version: PROTOCOL_VERSION,
    })? {
        ResponseBody::Handshake(h) => h,
        _ => bail!("expected handshake"),
    };
    handshake(&h)?;
    C::fingerprint(&h)?;
    let i = match session.exchange(RequestBody::Initialize {
        ledger_path: format!("{ROOT}/ledger"),
        initial_state: InitialState::SnapshotArchive {
            archive_path: SNAPSHOT.into(),
        },
        scratch_root: Some(format!("{ROOT}/scratch")),
    })? {
        ResponseBody::Initialized(i) => i,
        _ => bail!("expected initialized response"),
    };
    initialized(&i)?;
    C::initialized(&i)?;
    let c = match session.exchange(RequestBody::FreezeCheckpoint { slot: SLOT })? {
        ResponseBody::Checkpoint(c) => c,
        _ => bail!("expected canonical checkpoint"),
    };
    checkpoint(&c, i.next_write_version)?;
    C::frozen(&i, &c)?;
    C::match_original(&packet, &i, &c)?;
    let log_bytes = session.shutdown()?;
    ensure!(
        inputs()? == packet,
        "input evidence changed during native run"
    );
    save(
        "native-result.json",
        &json!({
            "schema":RESULT,"epoch":EPOCH,
            "worker":{"path":WORKER,"sha256":WORKER_SHA},"bootstrap_sha256":SNAPSHOT_SHA,
            "genesis_sha256":GENESIS_SHA,"bootstrap_slot":SLOT,"accounts_hash":ACCOUNTS_HASH,
            "full_accounts_commitment_verified":true,"worker_shutdown_acknowledged":true,"worker_reaped":true,
            "worker_pid":pid,"first_guard":gate,"handshake":h,"initialized":i,
            "checkpoint":c,"elapsed_seconds":start.elapsed().as_secs(),"stderr_bytes":log_bytes,
            "entry_replay":false,"snapshot_export":false,"downloads":false,
            "native_terminal_and_guard_history_acceptance_required":true,
            "admission_authorized":false,"replay_launch_authorized":false,"publication_authorized":false,
            "full_epoch_qualified":false,"remote_mutations":false,"r2_mutations":false
        }),
    )?;
    println!(
        "epoch{EPOCH} exact cold input completed; native PID1 and complete guard-history acceptance remain required"
    );
    Ok(())
}
fn finish(result: Result<()>) {
    if let Err(e) = result {
        eprintln!("epoch{EPOCH} cold input failed: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn good_checkpoint() -> Checkpoint {
        Checkpoint {
            slot: SLOT,
            bank_hash: vec![1; 32],
            accounts_hash: bs58::decode(ACCOUNTS_HASH).into_vec().unwrap(),
            last_blockhash: vec![2; 32],
            capitalization: 1,
            transaction_count: 1,
            tick_height: 1,
            slot_complete: true,
            writes: vec![],
            next_write_version: 0,
        }
    }
    #[test]
    fn checkpoint_rejects_wrong_hash_slot_partial_or_bootstrap_writes() {
        let c = good_checkpoint();
        checkpoint(&c, 0).unwrap();
        let mut bad = c.clone();
        bad.accounts_hash[0] ^= 1;
        assert!(checkpoint(&bad, 0).is_err());
        let mut bad = c.clone();
        bad.slot += 1;
        assert!(checkpoint(&bad, 0).is_err());
        let mut bad = c.clone();
        bad.slot_complete = false;
        assert!(checkpoint(&bad, 0).is_err());
        let mut bad = c;
        bad.next_write_version = 1;
        assert!(checkpoint(&bad, 0).is_err());
    }
    #[test]
    fn handshake_refuses_foreign_runtime_and_genesis() {
        let h = Handshake {
            protocol_version: PROTOCOL_VERSION,
            backend_id: BACKEND.into(),
            qualification: BackendQualification::Candidate,
            solana_tag: BACKEND.trim_start_matches("solana-").into(),
            solana_commit: SOLANA_COMMIT.into(),
            rust_toolchain: String::new(),
            target: String::new(),
            required_genesis_hash: MAINNET_GENESIS_HASH.into(),
        };
        handshake(&h).unwrap();
        let mut bad = h.clone();
        bad.protocol_version += 1;
        assert!(handshake(&bad).is_err());
        let mut bad = h.clone();
        bad.solana_commit = "foreign".into();
        assert!(handshake(&bad).is_err());
        let mut bad = h;
        bad.required_genesis_hash = "foreign".into();
        assert!(handshake(&bad).is_err());
    }
    #[test]
    fn initialization_refuses_genesis_and_wrong_snapshot() {
        let mut i = Initialized {
            genesis_hash: MAINNET_GENESIS_HASH.into(),
            source: InitializedSource::SnapshotArchive {
                archive_path: SNAPSHOT.into(),
                expected_accounts_hash: bs58::decode(ACCOUNTS_HASH).into_vec().unwrap(),
            },
            slot: SLOT,
            last_blockhash: vec![0; 32],
            ticks_per_slot: 64,
            next_write_version: 0,
        };
        initialized(&i).unwrap();
        i.source = InitializedSource::Genesis;
        assert!(initialized(&i).is_err());
    }
    #[test]
    fn read_timeout_and_log_failure_do_not_wait_for_worker_bytes() {
        use std::os::unix::net::UnixStream;
        let (a, _peer) = UnixStream::pair().unwrap();
        let signal = Arc::new(AtomicBool::new(false));
        let mut pipe = Pipe::new(a, Instant::now(), signal.clone()).unwrap();
        assert_eq!(
            pipe.read(&mut [0u8; 1]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        pipe.end = Instant::now() + Duration::from_secs(10);
        signal.store(true, Ordering::Release);
        assert!(pipe.read(&mut [0u8; 1]).is_err());
    }
}
