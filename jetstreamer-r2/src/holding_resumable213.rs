//! Opt-in Foundation 213 prefix-preserving byte restore. No remote mutations.
use super::*;
use futures_util::{StreamExt, stream};
use std::{future::Future, os::fd::AsRawFd};
const CONCURRENCY: usize = 8;
const RANGE: u64 = 32 << 20;
const BODY_ATTEMPTS: usize = 3;
const BODY_RETRY_WINDOW: std::time::Duration = std::time::Duration::from_secs(120);
const SDK_DOWNLOAD_STALL: &str =
    "minimum throughput was specified at 1 B/s, but throughput of 0 B/s was observed";
#[derive(Debug)]
struct RetryableBodyStall;
impl std::fmt::Display for RetryableBodyStall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("pinned SDK download body stalled")
    }
}
impl std::error::Error for RetryableBodyStall {}
fn body_interruption(error: anyhow::Error) -> anyhow::Error {
    // The pinned SDK's private throughput error has no public typed classifier.
    // Match its exact source message only here, after a streaming body error.
    // Header/identity/checksum/length/SHA/write errors never enter this path.
    let stalled = error
        .chain()
        .any(|cause| cause.to_string() == SDK_DOWNLOAD_STALL);
    let error = if stalled {
        error.context(RetryableBodyStall)
    } else {
        error
    };
    error.context("resumed holding range body interrupted")
}
#[derive(Clone, Debug, PartialEq)]
struct Stamp {
    regular: bool,
    dev: u64,
    ino: u64,
    len: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}
impl Stamp {
    fn of(m: &fs::Metadata) -> Self {
        Self {
            regular: m.is_file(),
            dev: m.dev(),
            ino: m.ino(),
            len: m.len(),
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode() & 0o7777,
            links: m.nlink(),
            mtime: m.mtime(),
            mtime_ns: m.mtime_nsec(),
            ctime: m.ctime(),
            ctime_ns: m.ctime_nsec(),
        }
    }
    fn continued(&self, initial: &Self, length: u64, mode: u32) -> Result<()> {
        self.partial(length)?;
        ensure!(
            self.dev == initial.dev
                && self.ino == initial.ino
                && self.uid == initial.uid
                && self.gid == initial.gid
                && self.len == length
                && self.mode == mode,
            "resumed partial identity/ownership/mode changed"
        );
        Ok(())
    }
    fn partial(&self, length: u64) -> Result<()> {
        ensure!(
            self.regular
                && self.uid == 0
                && self.links == 1
                && self.len <= length
                && matches!(self.mode, 0o600 | 0o400),
            "unsafe resumable holding partial"
        );
        ensure!(
            self.mode != 0o400 || self.len == length,
            "sealed holding partial is truncated"
        );
        Ok(())
    }
}
#[derive(Debug, Serialize)]
pub(super) struct Proof {
    pub(super) local_prefix_bytes: u64,
    pub(super) network_suffix_bytes: u64,
    pub(super) whole_file_sha256_verified: bool,
}
fn ranges(offset: u64, length: u64) -> Result<Vec<(u64, u64)>> {
    ensure!(offset <= length, "partial offset exceeds expected length");
    let mut result = Vec::new();
    let mut start = offset;
    while start < length {
        let end = start.saturating_add(RANGE).min(length);
        result.push((start, end));
        start = end;
    }
    Ok(result)
}
fn seed(file: &mut File) -> Result<(Sha256, u64, Stamp)> {
    let before = Stamp::of(&file.metadata()?);
    file.seek(SeekFrom::Start(0))?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 128 << 10];
    let mut hashed = 0u64;
    while hashed < before.len {
        let limit = usize::try_from((before.len - hashed).min(buffer.len() as u64))?;
        let n = file.read(&mut buffer[..limit])?;
        ensure!(n > 0, "partial prefix was truncated while hashing");
        digest.update(&buffer[..n]);
        hashed += n as u64;
    }
    ensure!(
        Stamp::of(&file.metadata()?) == before,
        "partial prefix changed while hashing"
    );
    Ok((digest, hashed, before))
}
async fn append<F, Fut, W>(
    spec: RemoteReadSpec<'_>,
    offset: u64,
    mut digest: Sha256,
    writer: &mut W,
    mut fetch: F,
) -> Result<()>
where
    F: FnMut(u64, u64) -> Fut,
    Fut: Future<Output = Result<Vec<u8>>>,
    W: Write,
{
    ensure!(
        spec.concurrency == CONCURRENCY
            && 2 * RANGE * CONCURRENCY as u64 <= REMOTE_READ_BUFFER_BUDGET,
        "resumable holding transport buffer contract differs"
    );
    let downloads = stream::iter(ranges(offset, spec.expected_length)?)
        .map(|(start, end)| {
            let request = fetch(start, end);
            async move { request.await.map(|bytes| (start, end, bytes)) }
        })
        .buffered(CONCURRENCY);
    futures_util::pin_mut!(downloads);
    let mut received = offset;
    while let Some(result) = downloads.next().await {
        let (start, end, bytes) = result?;
        ensure!(
            start == received && bytes.len() as u64 == end - start,
            "resumable suffix range length/order differs"
        );
        writer.write_all(&bytes)?;
        writer.flush()?;
        digest.update(&bytes);
        received = end;
    }
    ensure!(
        received == spec.expected_length,
        "resumable holding suffix truncated"
    );
    ensure!(
        hex_lower(&digest.finalize()) == spec.expected_sha256,
        "complete resumed holding SHA-256 mismatch"
    );
    Ok(())
}
async fn pinned_range(
    client: &Client,
    spec: RemoteReadSpec<'_>,
    start: u64,
    end: u64,
) -> Result<Vec<u8>> {
    // Preserve the first attempt's existing SDK/service time bounds. A fixed
    // retry deadline begins only after a positively classified body stall;
    // ordinary writer backpressure must not create a new initial timeout.
    let mut deadline = None;
    for attempt in 1..=BODY_ATTEMPTS {
        let result = if let Some(deadline) = deadline {
            tokio::time::timeout_at(deadline, pinned_range_once(client, spec, start, end))
                .await
                .context("resumed range body retry window exhausted")?
        } else {
            pinned_range_once(client, spec, start, end).await
        };
        match result {
            Err(error)
                if error.downcast_ref::<RetryableBodyStall>().is_some()
                    && attempt < BODY_ATTEMPTS =>
            {
                deadline.get_or_insert_with(|| tokio::time::Instant::now() + BODY_RETRY_WINDOW);
                // No bytes from this attempt escape its private Vec. Repeat
                // the exact complete range and If-Match under one fixed budget.
                eprintln!(
                    "{}",
                    json!({"event":"holding-resume-stalled-range-retry","start":start,"end":end,"failed_attempt":attempt,"maximum_attempts":BODY_ATTEMPTS,"fixed_window_millis":BODY_RETRY_WINDOW.as_millis()})
                );
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
            result => return result,
        }
    }
    unreachable!("bounded range attempts return on the final attempt")
}
async fn pinned_range_once(
    client: &Client,
    spec: RemoteReadSpec<'_>,
    start: u64,
    end: u64,
) -> Result<Vec<u8>> {
    ensure!(
        start < end && end <= spec.expected_length && end - start <= RANGE,
        "invalid resumed range"
    );
    let range = format!("bytes={start}-{}", end - 1);
    let expected_range = format!("bytes {start}-{}/{}", end - 1, spec.expected_length);
    // SDK request retries remain unchanged. Only the exact SDK download stall
    // from body polling can request a bounded whole-range repeat above.
    let response = client
        .get_object()
        .bucket(spec.bucket)
        .key(spec.key)
        .if_match(format!("\"{}\"", spec.etag))
        .range(&range)
        .send()
        .await
        .context("conditional resumable holding range request failed")?;
    ensure!(
        response
            .content_length()
            .and_then(|n| u64::try_from(n).ok())
            == Some(end - start),
        "resumed range Content-Length mismatch"
    );
    ensure!(
        response.content_range() == Some(expected_range.as_str()),
        "resumed range Content-Range mismatch"
    );
    ensure!(
        response.e_tag().map(normalize_etag) == Some(spec.etag),
        "resumed range ETag mismatch"
    );
    let mut body = response.body;
    let mut bytes = Vec::with_capacity(usize::try_from(end - start)?);
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(|error| body_interruption(anyhow::Error::new(error)))?;
        ensure!(
            bytes
                .len()
                .checked_add(chunk.len())
                .is_some_and(|n| n as u64 <= end - start),
            "resumed range body oversized"
        );
        bytes.extend_from_slice(&chunk);
    }
    ensure!(
        bytes.len() as u64 == end - start,
        "resumed range body truncated"
    );
    Ok(bytes)
}
fn seal_and_commit<F: Fn() -> Result<()>>(
    file: &File,
    partial: &Path,
    destination: &Path,
    verified: &Stamp,
    before_commit: F,
) -> Result<()> {
    verified.continued(verified, verified.len, verified.mode)?;
    ensure!(
        Stamp::of(&file.metadata()?) == *verified
            && Stamp::of(&fs::symlink_metadata(partial)?) == *verified,
        "verified partial changed before sealing"
    );
    file.set_permissions(fs::Permissions::from_mode(0o400))?;
    file.sync_all()?;
    File::open(partial.parent().context("resumed partial parent")?)?.sync_all()?;
    let sealed = Stamp::of(&file.metadata()?);
    sealed.continued(verified, verified.len, 0o400)?;
    before_commit()?;
    let after = Stamp::of(&file.metadata()?);
    after.continued(verified, verified.len, 0o400)?;
    ensure!(
        after == sealed && Stamp::of(&fs::symlink_metadata(partial)?) == sealed,
        "sealed resumed partial changed before commit"
    );
    rename_noreplace(partial, destination)
}
struct DurableFloor<'a> {
    inner: FloorWriter<'a>,
}
impl Write for DurableFloor<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.inner.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.file.sync_data()
    }
}
fn hash_complete(file: &mut File, path: &Path, length: u64, sha: &str) -> Result<Stamp> {
    let (digest, n, stamp) = seed(file)?;
    ensure!(
        n == length && hex_lower(&digest.finalize()) == sha,
        "complete local resumed holding SHA-256 mismatch"
    );
    ensure!(
        Stamp::of(&fs::symlink_metadata(path)?) == stamp,
        "resumed holding path changed during verification"
    );
    Ok(stamp)
}
fn verify_complete(
    file: &mut File,
    path: &Path,
    length: u64,
    sha: &str,
    initial: &Stamp,
) -> Result<Stamp> {
    Stamp::of(&file.metadata()?).continued(initial, length, initial.mode)?;
    let stamp = hash_complete(file, path, length, sha)?;
    stamp.continued(initial, length, initial.mode)?;
    Ok(stamp)
}
pub(super) async fn restore<F: Fn() -> Result<()>>(
    client: &Client,
    target: BlobRestore<'_>,
    before_commit: F,
) -> Result<(PathBuf, Proof)> {
    let BlobRestore {
        key,
        etag,
        sha,
        length,
        directory,
        minimum,
    } = target;
    private(directory)?;
    ensure!(
        length > 0 && is_lower_hex(sha, 64) && !etag.is_empty(),
        "invalid resumable holding identity"
    );
    let destination = directory.join(format!("{sha}.blob"));
    let partial = directory.join(format!(".{sha}.partial"));
    match fs::symlink_metadata(&destination) {
        Ok(m) => {
            let stamp = Stamp::of(&m);
            stamp.partial(length)?;
            ensure!(
                stamp.mode == 0o400 && stamp.len == length,
                "unsafe completed holding blob"
            );
            let mut f = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&destination)?;
            ensure!(
                Stamp::of(&f.metadata()?) == stamp,
                "holding destination changed while opening"
            );
            let verified = verify_complete(&mut f, &destination, length, sha, &stamp)?;
            before_commit()?;
            ensure!(
                Stamp::of(&f.metadata()?) == verified
                    && Stamp::of(&fs::symlink_metadata(&destination)?) == verified,
                "completed holding blob changed during admission"
            );
            return Ok((
                destination,
                Proof {
                    local_prefix_bytes: length,
                    network_suffix_bytes: 0,
                    whole_file_sha256_verified: true,
                },
            ));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    let mut file = match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&partial)
    {
        Ok(f) => {
            f.sync_all()?;
            File::open(directory)?.sync_all()?;
            f
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&partial)?,
        Err(e) => return Err(e.into()),
    };
    let stamp = Stamp::of(&file.metadata()?);
    stamp.partial(length)?;
    ensure!(
        Stamp::of(&fs::symlink_metadata(&partial)?) == stamp
            && unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "partial identity changed or another restore owns it"
    );
    let physical = file
        .metadata()?
        .blocks()
        .checked_mul(512)
        .context("resumable partial block overflow")?;
    ensure!(
        available(directory)?
            >= minimum
                .checked_add(length - stamp.len.min(physical))
                .context("resumable restore floor overflow")?,
        "resumable holding restore would consume protected space"
    );
    let local_prefix_bytes = stamp.len;
    let verified = if stamp.mode == 0o600 {
        let (digest, offset, hashed_stamp) = seed(&mut file)?;
        ensure!(
            hashed_stamp == stamp && Stamp::of(&fs::symlink_metadata(&partial)?) == stamp,
            "partial path changed during prefix rehash"
        );
        eprintln!(
            "{}",
            json!({"event":"holding-resume-prefix-rehashed","local_prefix_bytes":offset,"expected_length":length,"whole_file_sha256_verified":false})
        );
        let spec = RemoteReadSpec {
            bucket: BUCKET,
            key,
            etag,
            expected_length: length,
            expected_sha256: sha,
            concurrency: CONCURRENCY,
        };
        let result = {
            let mut writer = DurableFloor {
                inner: FloorWriter {
                    file: &mut file,
                    directory,
                    minimum_free_bytes: minimum,
                },
            };
            append(spec, offset, digest, &mut writer, |start, end| {
                pinned_range(client, spec, start, end)
            })
            .await
        };
        // Even a failed range/write leaves one contiguous partial. Preserve and
        // flush it; never truncate it or turn a partial hash into completion.
        file.sync_all()?;
        File::open(directory)?.sync_all()?;
        result?;
        verify_complete(&mut file, &partial, length, sha, &stamp)?
    } else {
        verify_complete(&mut file, &partial, length, sha, &stamp)?
    };
    seal_and_commit(&file, &partial, &destination, &verified, before_commit)?;
    Ok((
        destination,
        Proof {
            local_prefix_bytes,
            network_suffix_bytes: length - local_prefix_bytes,
            whole_file_sha256_verified: true,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::RefCell,
        net::{Shutdown, TcpListener},
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };
    fn body() -> Vec<u8> {
        (0..131087).map(|i| (i % 251) as u8).collect()
    }
    fn spec<'a>(sha: &'a str, length: u64) -> RemoteReadSpec<'a> {
        RemoteReadSpec {
            bucket: "fixture",
            key: "prefix.blob",
            etag: "pinned",
            expected_length: length,
            expected_sha256: sha,
            concurrency: CONCURRENCY,
        }
    }
    fn fixture_file(bytes: &[u8]) -> (tempfile::TempDir, PathBuf, File) {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("partial");
        let mut f = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(&p)
            .unwrap();
        f.write_all(bytes).unwrap();
        (d, p, f)
    }
    fn monitored_client(endpoint: String) -> Client {
        Client::from_conf(
            client(endpoint)
                .config()
                .to_builder()
                .stalled_stream_protection(
                    aws_sdk_s3::config::StalledStreamProtectionConfig::enabled()
                        .grace_period(Duration::ZERO)
                        .build(),
                )
                .build(),
        )
    }
    fn monitored_server(
        body: Arc<Vec<u8>>,
        faults: Vec<&'static str>,
        writer_pause: Option<Arc<std::sync::atomic::AtomicBool>>,
    ) -> (
        Client,
        std::thread::JoinHandle<()>,
        Arc<Mutex<Vec<(u64, u64)>>>,
    ) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = seen.clone();
        let opened = Arc::new(AtomicUsize::new(0));
        let join = std::thread::spawn(move || {
            let mut handlers = Vec::new();
            for fault in faults {
                let deadline = Instant::now() + Duration::from_secs(10);
                let (mut socket, _) = loop {
                    match listener.accept() {
                        Ok(s) => break s,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline);
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        Err(e) => panic!("{e}"),
                    }
                };
                let body = body.clone();
                let recorded = recorded.clone();
                let opened = opened.clone();
                let writer_pause = writer_pause.clone();
                handlers.push(std::thread::spawn(move || {
                    socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                    socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
                    let mut raw=Vec::new();while !raw.ends_with(b"\r\n\r\n") {let mut byte=[0];socket.read_exact(&mut byte).unwrap();raw.push(byte[0]);assert!(raw.len()<16384);}
                    let request=String::from_utf8(raw).unwrap().to_lowercase();assert!(request.contains("if-match: \"pinned\"\r\n"));
                    let r=request.lines().find_map(|line|line.strip_prefix("range: bytes=")).unwrap();let (a,b)=r.split_once('-').unwrap();let start=a.parse::<u64>().unwrap();let end=b.parse::<u64>().unwrap()+1;
                    assert!(start<end && end<=body.len() as u64);recorded.lock().unwrap().push((start,end));
                    let etag=if fault=="etag" {"changed"} else {"pinned"};
                    let header=format!("HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {start}-{}/{}\r\nETag: \"{etag}\"\r\nConnection: close\r\n\r\n",end-start,end-1,body.len());
                    socket.write_all(header.as_bytes()).unwrap();opened.fetch_add(1,Ordering::SeqCst);
                    let bytes=&body[start as usize..end as usize];
                    if let Some(pause)=writer_pause {
                        let deadline=Instant::now()+Duration::from_secs(8);
                        if start==0 {
                            while opened.load(Ordering::SeqCst)<2 {assert!(Instant::now()<deadline);std::thread::sleep(Duration::from_millis(2));}
                            let _=socket.write_all(bytes);
                        } else {
                            let _=socket.write_all(&bytes[..1]);
                            while !pause.load(Ordering::SeqCst) {assert!(Instant::now()<deadline);std::thread::sleep(Duration::from_millis(2));}
                            let _=socket.write_all(&bytes[1..]);
                        }
                    } else if fault=="stall" {
                        let _=socket.write_all(&bytes[..bytes.len()/2]);
                        std::thread::sleep(Duration::from_millis(2500));
                    } else {let _=socket.write_all(bytes);}
                    let _=socket.shutdown(Shutdown::Both);
                }));
            }
            for handler in handlers {
                handler.join().unwrap();
            }
        });
        (monitored_client(endpoint), join, seen)
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_sdk_stalled_body_retries_exact_whole_range_and_exhaustion_preserves_prefix() {
        let body = Arc::new(body());
        let sha = hex_lower(&Sha256::digest(body.as_slice()));
        for faults in [
            vec!["stall", "ok"],
            vec!["stall", "stall", "stall"],
            vec!["stall", "etag"],
        ] {
            let expected = faults.len();
            let recover = faults.last() == Some(&"ok");
            let identity = faults.last() == Some(&"etag");
            let (client, join, seen) = monitored_server(body.clone(), faults, None);
            let (_d, p, mut file) = fixture_file(&body[..37]);
            let (digest, start, _) = seed(&mut file).unwrap();
            let s = spec(&sha, body.len() as u64);
            let result = tokio::time::timeout(
                Duration::from_secs(12),
                append(s, start, digest, &mut file, |a, b| {
                    pinned_range(&client, s, a, b)
                }),
            )
            .await
            .unwrap();
            join.join().unwrap();
            assert_eq!(
                *seen.lock().unwrap(),
                vec![(37, body.len() as u64); expected]
            );
            if recover {
                result.unwrap();
                assert_eq!(fs::read(&p).unwrap(), body.as_slice());
            } else {
                let error = result.unwrap_err();
                if identity {
                    assert!(error.to_string().contains("ETag mismatch"), "{error:#}");
                } else {
                    assert!(
                        error
                            .chain()
                            .any(|cause| cause.to_string() == SDK_DOWNLOAD_STALL),
                        "{error:#}"
                    );
                }
                assert_eq!(fs::read(&p).unwrap(), body[..37]);
                assert_eq!(fs::metadata(&p).unwrap().mode() & 0o777, 0o600);
            }
        }
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn actual_sdk_body_exempts_slow_writer_no_polling_without_any_range_retry() {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct SlowWriter {
            bytes: Vec<u8>,
            pause: Arc<AtomicBool>,
            paused: bool,
        }
        impl Write for SlowWriter {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.bytes.extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                if !self.paused {
                    self.paused = true;
                    self.pause.store(true, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(1500));
                }
                Ok(())
            }
        }
        let body = Arc::new(
            (0..RANGE as usize + 131087)
                .map(|i| (i % 251) as u8)
                .collect::<Vec<_>>(),
        );
        let sha = hex_lower(&Sha256::digest(body.as_slice()));
        let pause = Arc::new(AtomicBool::new(false));
        let (client, join, seen) =
            monitored_server(body.clone(), vec!["ok", "ok"], Some(pause.clone()));
        let mut writer = SlowWriter {
            bytes: Vec::new(),
            pause,
            paused: false,
        };
        let s = spec(&sha, body.len() as u64);
        tokio::time::timeout(
            Duration::from_secs(12),
            append(s, 0, Sha256::new(), &mut writer, |a, b| {
                pinned_range(&client, s, a, b)
            }),
        )
        .await
        .unwrap()
        .unwrap();
        join.join().unwrap();
        assert!(writer.paused);
        assert_eq!(writer.bytes, body.as_slice());
        let mut requests = seen.lock().unwrap().clone();
        requests.sort_unstable();
        assert_eq!(requests, vec![(0, RANGE), (RANGE, body.len() as u64)]);
    }
    #[test]
    fn only_exact_sdk_body_stall_is_retryable_and_attempt_budget_is_fixed() {
        let known = body_interruption(anyhow::anyhow!(SDK_DOWNLOAD_STALL));
        assert!(known.downcast_ref::<RetryableBodyStall>().is_some());
        for message in [
            "checksum mismatch",
            "resumed range ETag mismatch",
            "body truncated",
            "unrelated streaming error",
        ] {
            assert!(
                body_interruption(anyhow::anyhow!(message))
                    .downcast_ref::<RetryableBodyStall>()
                    .is_none()
            );
        }
        assert_eq!(BODY_ATTEMPTS, 3);
        assert_eq!(BODY_RETRY_WINDOW, Duration::from_secs(120));
        assert_eq!(CONCURRENCY, 8);
        assert_eq!(2 * RANGE * CONCURRENCY as u64, REMOTE_READ_BUFFER_BUDGET);
    }
    #[tokio::test]
    async fn every_arbitrary_prefix_offset_rehashes_then_requests_only_the_missing_suffix() {
        let body = body();
        let sha = hex_lower(&Sha256::digest(&body));
        for offset in [0, 1, 31, 65537, body.len() - 1, body.len()] {
            let (_d, p, mut f) = fixture_file(&body[..offset]);
            let (digest, start, _) = seed(&mut f).unwrap();
            let calls = RefCell::new(Vec::new());
            append(
                spec(&sha, body.len() as u64),
                start,
                digest,
                &mut f,
                |a, b| {
                    calls.borrow_mut().push((a, b));
                    std::future::ready(Ok(body[a as usize..b as usize].to_vec()))
                },
            )
            .await
            .unwrap();
            assert_eq!(fs::read(&p).unwrap(), body);
            hash_complete(&mut f, &p, body.len() as u64, &sha).unwrap();
            assert_eq!(
                calls.borrow().first().map(|r| r.0),
                if offset == body.len() {
                    None
                } else {
                    Some(offset as u64)
                }
            );
        }
        assert_eq!(2 * RANGE * CONCURRENCY as u64, REMOTE_READ_BUFFER_BUDGET);
        let r = ranges(37, 3 * RANGE + 9).unwrap();
        assert_eq!(r[0].0, 37);
        for p in r.windows(2) {
            assert_eq!(p[0].1, p[1].0);
        }
        assert!(ranges(10, 9).is_err());
    }
    struct Interrupted<'a> {
        file: &'a mut File,
        left: usize,
    }
    impl Write for Interrupted<'_> {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            if self.left == 0 {
                return Err(std::io::Error::other("fixture interrupted write"));
            }
            let n = b.len().min(self.left);
            let n = self.file.write(&b[..n])?;
            self.left -= n;
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.file.sync_data()
        }
    }
    #[tokio::test]
    async fn interruption_mid_range_preserves_contiguous_bytes_and_next_attempt_starts_exactly_there()
     {
        let body = body();
        let sha = hex_lower(&Sha256::digest(&body));
        let (_d, p, mut f) = fixture_file(&body[..37]);
        let (digest, start, _) = seed(&mut f).unwrap();
        let mut writer = Interrupted {
            file: &mut f,
            left: 19,
        };
        assert!(
            append(
                spec(&sha, body.len() as u64),
                start,
                digest,
                &mut writer,
                |a, b| std::future::ready(Ok(body[a as usize..b as usize].to_vec()))
            )
            .await
            .is_err()
        );
        assert_eq!(fs::read(&p).unwrap(), body[..56]);
        let (digest, start, _) = seed(&mut f).unwrap();
        assert_eq!(start, 56);
        append(
            spec(&sha, body.len() as u64),
            start,
            digest,
            &mut f,
            |a, b| std::future::ready(Ok(body[a as usize..b as usize].to_vec())),
        )
        .await
        .unwrap();
        hash_complete(&mut f, &p, body.len() as u64, &sha).unwrap();
    }
    #[tokio::test]
    async fn corrupt_prefix_and_post_seed_corruption_never_become_a_complete_proof() {
        use std::os::unix::fs::FileExt;
        let body = body();
        let sha = hex_lower(&Sha256::digest(&body));
        let mut bad = body[..37].to_vec();
        bad[0] ^= 1;
        let (_d, p, mut f) = fixture_file(&bad);
        let (digest, start, _) = seed(&mut f).unwrap();
        assert!(
            append(
                spec(&sha, body.len() as u64),
                start,
                digest,
                &mut f,
                |a, b| std::future::ready(Ok(body[a as usize..b as usize].to_vec()))
            )
            .await
            .is_err()
        );
        assert!(hash_complete(&mut f, &p, body.len() as u64, &sha).is_err());
        let (_d, p, mut f) = fixture_file(&body[..37]);
        let (digest, start, _) = seed(&mut f).unwrap();
        f.write_at(&[255], 0).unwrap();
        append(
            spec(&sha, body.len() as u64),
            start,
            digest,
            &mut f,
            |a, b| std::future::ready(Ok(body[a as usize..b as usize].to_vec())),
        )
        .await
        .unwrap();
        assert!(hash_complete(&mut f, &p, body.len() as u64, &sha).is_err());
        assert_eq!(fs::metadata(&p).unwrap().mode() & 0o777, 0o600);
    }
    #[test]
    fn partial_policy_rejects_truncation_oversize_alias_owner_and_mid_download_mode_changes() {
        use std::os::unix::fs::symlink;
        let (_d, p, f) = fixture_file(b"known prefix");
        let mut initial = Stamp::of(&f.metadata().unwrap());
        initial.uid = 0;
        initial.partial(initial.len + 1).unwrap();
        let mut full = initial.clone();
        full.len += 1;
        full.continued(&initial, full.len, 0o600).unwrap();
        for (kind, mut bad) in [
            ("uid", full.clone()),
            ("alias", full.clone()),
            ("mode", full.clone()),
            ("inode", full.clone()),
        ] {
            match kind {
                "uid" => bad.uid = 1000,
                "alias" => bad.links = 2,
                "mode" => bad.mode = 0o400,
                _ => bad.ino += 1,
            };
            assert!(bad.continued(&initial, full.len, 0o600).is_err(), "{kind}");
        }
        let mut bad = initial.clone();
        bad.mode = 0o400;
        assert!(bad.partial(initial.len + 1).is_err());
        assert!(initial.partial(initial.len - 1).is_err());
        let alias = p.with_extension("alias");
        fs::hard_link(&p, &alias).unwrap();
        let mut aliased = Stamp::of(&f.metadata().unwrap());
        aliased.uid = 0;
        assert!(aliased.partial(initial.len + 1).is_err());
        fs::remove_file(&alias).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o400)).unwrap();
        let mut changed = Stamp::of(&f.metadata().unwrap());
        changed.uid = 0;
        assert!(changed.continued(&initial, initial.len, 0o600).is_err());
        symlink(&p, &alias).unwrap();
        assert!(
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&alias)
                .is_err()
        );
    }
    #[tokio::test]
    #[ignore = "root-only disposable fixture; no host/R2 paths or real endpoint"]
    async fn root_fixture_stale_admission_reuses_sealed_partial_and_conflicting_identity_never_commits()
     {
        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "run only this exact disposable fixture as root"
        );
        let body = body();
        let sha = hex_lower(&Sha256::digest(&body));
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let partial = dir.path().join(format!(".{sha}.partial"));
        fs::write(&partial, &body[..37]).unwrap();
        fs::set_permissions(&partial, fs::Permissions::from_mode(0o600)).unwrap();
        let (http_client, join, _) = server(body.clone(), 37, "ok");
        let target = || BlobRestore {
            key: "prefix.blob",
            etag: "pinned",
            sha: &sha,
            length: body.len() as u64,
            directory: dir.path(),
            minimum: 0,
        };
        let error = restore(&http_client, target(), || {
            anyhow::bail!("fixture stale admission")
        })
        .await
        .unwrap_err();
        assert!(error.to_string().contains("stale admission"), "{error:#}");
        join.join().unwrap();
        assert_eq!(fs::metadata(&partial).unwrap().mode() & 0o777, 0o400);
        assert!(!dir.path().join(format!("{sha}.blob")).exists());
        assert_eq!(fs::read(&partial).unwrap(), body);
        let unused_client = client("http://127.0.0.1:1".into());
        let (path, proof) = tokio::time::timeout(
            Duration::from_secs(3),
            restore(&unused_client, target(), || Ok(())),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(proof.local_prefix_bytes, body.len() as u64);
        assert_eq!(proof.network_suffix_bytes, 0);
        assert!(proof.whole_file_sha256_verified);
        assert_eq!(fs::read(path).unwrap(), body);
        for fault in ["alias", "owner", "mode"] {
            let (d, p, mut f) = fixture_file(&body);
            let initial = Stamp::of(&f.metadata().unwrap());
            let (_digest, _, _) = seed(&mut f).unwrap();
            match fault {
                "alias" => fs::hard_link(&p, d.path().join("alias")).unwrap(),
                "owner" => assert_eq!(unsafe { libc::fchown(f.as_raw_fd(), 1000, 1000) }, 0),
                _ => fs::set_permissions(&p, fs::Permissions::from_mode(0o400)).unwrap(),
            };
            assert!(
                verify_complete(&mut f, &p, body.len() as u64, &sha, &initial).is_err(),
                "{fault}"
            );
            assert_eq!(fs::read(&p).unwrap(), body);
        }
        for fault in ["alias", "owner", "mode"] {
            let (d, p, mut f) = fixture_file(&body);
            let initial = Stamp::of(&f.metadata().unwrap());
            let verified = verify_complete(&mut f, &p, body.len() as u64, &sha, &initial).unwrap();
            let destination = d.path().join("complete.blob");
            assert!(
                seal_and_commit(&f, &p, &destination, &verified, || {
                    match fault {
                        "alias" => fs::hard_link(&p, d.path().join("alias"))?,
                        "owner" => ensure!(
                            unsafe { libc::fchown(f.as_raw_fd(), 1000, 1000) } == 0,
                            "fixture owner change"
                        ),
                        _ => fs::set_permissions(&p, fs::Permissions::from_mode(0o600))?,
                    };
                    Ok(())
                })
                .is_err(),
                "{fault}"
            );
            assert!(!destination.exists());
            assert_eq!(fs::read(&p).unwrap(), body);
        }
    }
    fn client(endpoint: String) -> Client {
        Client::from_conf(
            S3ConfigBuilder::new()
                .behavior_version(BehaviorVersion::latest())
                .region(Region::new("auto"))
                .credentials_provider(SharedCredentialsProvider::new(Credentials::new(
                    "fixture", "fixture", None, None, "fixture",
                )))
                .endpoint_url(endpoint)
                .force_path_style(true)
                .build(),
        )
    }
    fn server(
        body: Vec<u8>,
        offset: u64,
        fault: &'static str,
    ) -> (Client, std::thread::JoinHandle<()>, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = seen.clone();
        let join = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            let (mut socket, _) = loop {
                match listener.accept() {
                    Ok(s) => break s,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline);
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("{e}"),
                }
            };
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut raw = Vec::new();
            while !raw.ends_with(b"\r\n\r\n") {
                let mut b = [0];
                socket.read_exact(&mut b).unwrap();
                raw.push(b[0]);
                assert!(raw.len() < 16384);
            }
            let request = String::from_utf8(raw).unwrap().to_lowercase();
            assert!(request.contains("if-match: \"pinned\"\r\n"));
            assert!(request.contains(&format!("range: bytes={offset}-{}\r\n", body.len() - 1)));
            recorded.lock().unwrap().push(request);
            let suffix = &body[offset as usize..];
            let etag = if fault == "etag" { "changed" } else { "pinned" };
            let start = if fault == "range" { 0 } else { offset };
            let length = suffix.len() + usize::from(fault == "length");
            let header = if fault == "stale" {
                "HTTP/1.1 412 Precondition Failed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .into()
            } else {
                format!(
                    "HTTP/1.1 206 Partial Content\r\nContent-Length: {length}\r\nContent-Range: bytes {start}-{}/{}\r\nETag: \"{etag}\"\r\nConnection: close\r\n\r\n",
                    body.len() - 1,
                    body.len()
                )
            };
            let _ = socket.write_all(header.as_bytes());
            if fault != "stale" {
                let n = if fault == "interrupt" {
                    suffix.len() / 2
                } else {
                    suffix.len()
                };
                let _ = socket.write_all(&suffix[..n]);
            }
            let _ = socket.shutdown(Shutdown::Both);
        });
        (client(endpoint), join, seen)
    }
    #[tokio::test]
    async fn actual_conditional_http_ranges_pin_offset_etag_range_length_and_interrupted_body() {
        let body = body();
        let sha = hex_lower(&Sha256::digest(&body));
        for fault in ["ok", "etag", "range", "length", "interrupt", "stale"] {
            let (client, join, seen) = server(body.clone(), 37, fault);
            let s = spec(&sha, body.len() as u64);
            let result = tokio::time::timeout(
                Duration::from_secs(12),
                pinned_range(&client, s, 37, body.len() as u64),
            )
            .await
            .unwrap();
            join.join().unwrap();
            assert_eq!(seen.lock().unwrap().len(), 1);
            if fault == "ok" {
                assert_eq!(result.unwrap(), body[37..]);
            } else {
                assert!(result.is_err(), "{fault}");
            }
        }
    }
    #[tokio::test]
    async fn network_fault_keeps_existing_prefix_and_a_new_actual_request_resumes_from_same_offset()
    {
        let body = body();
        let sha = hex_lower(&Sha256::digest(&body));
        let (_d, p, mut f) = fixture_file(&body[..37]);
        let s = spec(&sha, body.len() as u64);
        let (client, join, _) = server(body.clone(), 37, "interrupt");
        let (digest, start, _) = seed(&mut f).unwrap();
        assert!(
            append(s, start, digest, &mut f, |a, b| pinned_range(
                &client, s, a, b
            ))
            .await
            .is_err()
        );
        join.join().unwrap();
        assert_eq!(fs::read(&p).unwrap(), body[..37]);
        let (http_client, join, _) = server(body.clone(), 37, "ok");
        let (digest, start, _) = seed(&mut f).unwrap();
        append(s, start, digest, &mut f, |a, b| {
            pinned_range(&http_client, s, a, b)
        })
        .await
        .unwrap();
        join.join().unwrap();
        hash_complete(&mut f, &p, body.len() as u64, &sha).unwrap();
    }
}
