//! Anonymous HTTP range reads bound to the authenticated archive inventory.
use std::{
    collections::BTreeMap,
    io,
    num::NonZeroUsize,
    ops::Range,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use reqwest::{Client, StatusCode, Url, header};
use serde::Deserialize;
use tokio::{
    sync::{Semaphore, SemaphorePermit},
    time::Instant,
};

#[derive(Clone, Debug, Deserialize)]
pub(super) struct Object {
    epoch: u64,
    key: String,
    etag: String,
    bytes: u64,
}

// Cap cache bytes across the worker set. Probe reads use their exact requested
// span and the same per-reader bound. Ordinary small audits keep 8 MiB reads.
const MAX_READ: usize = 8 << 20;
const TOTAL_READ_AHEAD: usize = 512 << 20;
const MAX_HTTP_REQUESTS: usize = 16;
const STANDARD_HTTP_ATTEMPTS: u32 = 3;
// Short origin-wide outages have exhausted three attempts and discarded
// hours of playback. Seven attempts allow 126 seconds of bounded backoff.
const SERVER_HTTP_ATTEMPTS: u32 = 7;

/// Decoding uses one worker per partition. Bound simultaneous HTTP requests
/// separately and honor an origin's Retry-After across every pinned reader.
#[derive(Debug)]
struct RequestBudget {
    permits: Semaphore,
    resume: Mutex<Instant>,
}

impl RequestBudget {
    fn new() -> Self {
        Self {
            permits: Semaphore::new(MAX_HTTP_REQUESTS),
            resume: Mutex::new(Instant::now()),
        }
    }

    async fn acquire(&self) -> SemaphorePermit<'_> {
        let permit = self
            .permits
            .acquire()
            .await
            .expect("request budget remains open");
        loop {
            let resume = *self.resume.lock().expect("request deadline");
            if resume <= Instant::now() {
                return permit;
            }
            tokio::time::sleep_until(resume).await;
        }
    }

    async fn open_range<'a>(
        &'a self,
        client: &Client,
        url: &Url,
        range: &str,
        etag: Option<&str>,
        attempt: u32,
    ) -> io::Result<Option<(reqwest::Response, SemaphorePermit<'a>)>> {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_secs(1 << attempt)).await;
        }
        let permit = self.acquire().await;
        let mut request = client
            .get(url.clone())
            .header(header::ACCEPT_ENCODING, "identity")
            .header(header::RANGE, range)
            .timeout(Duration::from_secs(180));
        if let Some(tag) = etag {
            request = request.header(header::IF_MATCH, tag);
        }
        let response = request.send().await;
        let response = match response {
            Err(_) if attempt + 1 < STANDARD_HTTP_ATTEMPTS => return Ok(None),
            Err(error) => {
                return Err(io::Error::other(format!(
                    "public archive transport: {error}"
                )));
            }
            Ok(response)
                if response.status() == StatusCode::TOO_MANY_REQUESTS
                    || (response.status() == StatusCode::SERVICE_UNAVAILABLE
                        && response.headers().contains_key(header::RETRY_AFTER)) =>
            {
                self.defer(
                    response.headers().get(header::RETRY_AFTER),
                    attempt.min(STANDARD_HTTP_ATTEMPTS - 1),
                )?;
                if attempt + 1 >= STANDARD_HTTP_ATTEMPTS {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        format!(
                            "public archive temporarily unavailable: {} at {range}",
                            response.status()
                        ),
                    ));
                }
                return Ok(None);
            }
            Ok(response) if response.status().is_server_error() => {
                if attempt + 1 < SERVER_HTTP_ATTEMPTS {
                    return Ok(None);
                }
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!(
                        "public archive HTTP server error after {SERVER_HTTP_ATTEMPTS} attempts: {} at {range}",
                        response.status()
                    ),
                ));
            }
            Ok(response) => response,
        };
        Ok(Some((response, permit)))
    }

    fn defer(&self, retry_after: Option<&header::HeaderValue>, attempt: u32) -> io::Result<()> {
        let delay = if let Some(value) = retry_after {
            let text = value.to_str().map_err(io::Error::other)?;
            if let Ok(seconds) = text.parse::<u64>() {
                Duration::from_secs(seconds)
            } else {
                httpdate::parse_http_date(text)
                    .map_err(io::Error::other)?
                    .duration_since(SystemTime::now())
                    .unwrap_or_default()
            }
        } else {
            Duration::from_secs(15 << attempt)
        };
        if delay > Duration::from_secs(180) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "public archive Retry-After exceeds request timeout",
            ));
        }
        let deadline = Instant::now() + delay;
        let mut resume = self.resume.lock().expect("request deadline");
        *resume = (*resume).max(deadline);
        Ok(())
    }
}

fn read_ahead(workers: usize) -> usize {
    (TOTAL_READ_AHEAD / workers.max(1)).clamp(1, MAX_READ)
}

/// A public strong validator observed once while loading the ordinary epoch layout.
/// It permits resuming interrupted rseek reads against the same representation.
pub(super) struct HttpRecovery {
    object: Object,
    url: Url,
    client: Client,
    budget: RequestBudget,
}

impl HttpRecovery {
    pub(super) async fn discover(
        client: &Client,
        base: &Url,
        epoch: u64,
    ) -> io::Result<Option<Arc<Self>>> {
        let key = format!("epoch-{epoch}.jet");
        let url = base.join(&key).map_err(io::Error::other)?;
        let budget = RequestBudget::new();
        let mut attempt = 0;
        let response = loop {
            if let Some((response, _permit)) = budget
                .open_range(client, &url, "bytes=0-0", None, attempt)
                .await?
            {
                break response.error_for_status().map_err(io::Error::other)?;
            }
            attempt += 1;
        };
        let Some(etag) = response
            .headers()
            .get(header::ETAG)
            .and_then(|h| h.to_str().ok())
            .filter(|tag| strong_etag(tag))
        else {
            // Legacy sources without a validator retain the uninterrupted rseek path.
            return Ok(None);
        };
        let bytes = response
            .headers()
            .get(header::CONTENT_RANGE)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("bytes 0-0/"))
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|n| *n > 0);
        let bytes = bytes
            .filter(|_| response.status() == StatusCode::PARTIAL_CONTENT)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid public archive identity probe",
                )
            })?;
        log::debug!(target: "jetstreamer_horizon_range", "horizon_http_identity epoch={epoch} bytes={bytes} etag={etag}");
        Ok(Some(Arc::new(Self {
            object: Object {
                epoch,
                key,
                etag: etag.to_owned(),
                bytes,
            },
            url: response.url().clone(),
            client: client.clone(),
            budget,
        })))
    }

    pub(super) fn request(&self) -> reqwest::RequestBuilder {
        self.client
            .get(self.url.clone())
            .header(header::IF_MATCH, &self.object.etag)
            .header(header::ACCEPT_ENCODING, "identity")
    }

    pub(super) fn len(&self) -> u64 {
        self.object.bytes
    }

    pub(super) async fn resume(&self, mut offset: u64, remaining: &mut [u8]) -> io::Result<()> {
        if offset
            .checked_add(remaining.len() as u64)
            .is_none_or(|end| end > self.len())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "resume exceeds original archive",
            ));
        }
        log::warn!(target: "jetstreamer_horizon_range",
            "resuming epoch {} at byte {offset} ({} unread bytes in this range)", self.object.epoch, remaining.len());
        for part in remaining.chunks_mut(MAX_READ) {
            Reader::fetch(
                &self.budget,
                &self.client,
                &self.url,
                &self.object,
                offset,
                part,
            )
            .await?;
            offset += part.len() as u64;
        }
        Ok(())
    }
}

fn strong_etag(tag: &str) -> bool {
    let bytes = tag.as_bytes();
    bytes.len() >= 3
        && bytes.first() == Some(&b'"')
        && bytes.last() == Some(&b'"')
        && bytes[1..bytes.len() - 1]
            .iter()
            .all(|b| b.is_ascii_graphic() && *b != b'"')
}

/// The immutable public origin and canonical archive identities of one audit.
#[derive(Clone, Debug)]
pub struct PinnedArchives {
    base: Url,
    objects: Arc<BTreeMap<u64, Object>>,
    budget: Arc<RequestBudget>,
    read_ahead: usize,
    pub(super) max_active_partitions: Option<NonZeroUsize>,
}

impl PinnedArchives {
    /// Loads a manifest containing an `objects` array with epoch, key, bytes and
    /// strong quoted ETag for every archive to be consumed.
    pub fn load(base: &str, path: &Path) -> io::Result<Self> {
        #[derive(Deserialize)]
        struct Manifest {
            objects: Vec<Object>,
        }
        let base =
            Url::parse(&format!("{}/", base.trim_end_matches('/'))).map_err(io::Error::other)?;
        if base.scheme() != "https"
            || base.host().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
        {
            return Err(io::Error::other(
                "public playback requires an anonymous HTTPS base URL",
            ));
        }
        let file = std::fs::File::open(path)?;
        if file.metadata()?.len() > 8 << 20 {
            return Err(io::Error::other("archive inventory exceeds 8 MiB"));
        }
        let manifest: Manifest = serde_json::from_reader(file)?;
        let mut objects = BTreeMap::new();
        for object in manifest.objects {
            if object.key != format!("epoch-{}.jet", object.epoch)
                || object.bytes == 0
                || !strong_etag(&object.etag)
                || objects.insert(object.epoch, object).is_some()
            {
                return Err(io::Error::other("invalid or duplicate archive identity"));
            }
        }
        Ok(Self {
            base,
            objects: Arc::new(objects),
            budget: Arc::new(RequestBudget::new()),
            read_ahead: MAX_READ,
            max_active_partitions: None,
        })
    }

    /// Limits simultaneously resident slot-range partitions, preserving each
    /// partition's worker ID, slot boundaries and verification digest.
    pub fn with_max_active_partitions(mut self, limit: NonZeroUsize) -> Self {
        self.max_active_partitions = Some(limit);
        self
    }

    pub(super) fn set_worker_count(&mut self, workers: usize) {
        self.read_ahead = read_ahead(workers);
    }

    pub(super) fn compact(&self) -> bool {
        self.read_ahead < MAX_READ
    }

    pub(super) fn open(
        &self,
        epoch: u64,
        client: &Client,
        worker_span: Option<Range<u64>>,
    ) -> io::Result<Reader> {
        let object = self
            .objects
            .get(&epoch)
            .ok_or_else(|| io::Error::other("epoch absent from pinned inventory"))?;
        if worker_span
            .as_ref()
            .is_some_and(|r| r.is_empty() || r.end > object.bytes)
        {
            return Err(io::Error::other(
                "worker bucket span exceeds pinned archive",
            ));
        }
        Ok(Reader {
            url: self.base.join(&object.key).map_err(io::Error::other)?,
            object: object.clone(),
            client: client.clone(),
            budget: Arc::clone(&self.budget),
            worker_span,
            cached: 0..0,
            read_ahead: self.read_ahead,
            cache: Vec::new(),
        })
    }
}

pub(super) struct Reader {
    url: Url,
    object: Object,
    client: Client,
    budget: Arc<RequestBudget>,
    worker_span: Option<Range<u64>>,
    cached: Range<u64>,
    read_ahead: usize,
    cache: Vec<u8>,
}

impl Reader {
    pub(super) fn log_verified_layout(&self) {
        log::debug!(target: "jetstreamer_horizon_range",
            "horizon_archive epoch={} url={} bytes={} etag={}",
            self.object.epoch, self.url, self.object.bytes, self.object.etag);
    }

    pub fn len(&self) -> u64 {
        self.object.bytes
    }

    async fn fetch(
        budget: &RequestBudget,
        client: &Client,
        url: &Url,
        object: &Object,
        start: u64,
        dest: &mut [u8],
    ) -> io::Result<()> {
        let count = dest.len() as u64;
        let end = start + count - 1;
        let range = format!("bytes={start}-{end}");
        let expected = format!("bytes {start}-{end}/{}", object.bytes);
        let mut attempt = 0;
        loop {
            let response = budget
                .open_range(client, url, &range, Some(&object.etag), attempt)
                .await?;
            attempt += 1;
            let Some((mut response, _permit)) = response else {
                continue;
            };
            let headers = response.headers();
            if response.url() != url
                || response.status() != StatusCode::PARTIAL_CONTENT
                || headers.get(header::ETAG).and_then(|v| v.to_str().ok())
                    != Some(object.etag.as_str())
                || headers
                    .get(header::CONTENT_RANGE)
                    .and_then(|v| v.to_str().ok())
                    != Some(expected.as_str())
                || response.content_length() != Some(count)
            {
                return Err(io::Error::other(format!(
                    "public archive HTTP status or range identity mismatch: {} at {range}",
                    response.status()
                )));
            }
            let mut written = 0;
            loop {
                match response.chunk().await {
                    Ok(Some(chunk)) => {
                        if chunk.len() > dest.len() - written {
                            return Err(io::Error::other("oversized public range"));
                        }
                        dest[written..written + chunk.len()].copy_from_slice(&chunk);
                        written += chunk.len();
                    }
                    Ok(None) if written == dest.len() => return Ok(()),
                    Ok(None) if attempt < STANDARD_HTTP_ATTEMPTS => break,
                    Ok(None) => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "public archive transport: incomplete range after retries",
                        ));
                    }
                    Err(_) if attempt < STANDARD_HTTP_ATTEMPTS => break,
                    Err(error) => {
                        return Err(io::Error::other(format!(
                            "public archive transport: {error}"
                        )));
                    }
                }
            }
        }
    }

    pub async fn read_at(&mut self, mut offset: u64, mut dest: &mut [u8]) -> io::Result<()> {
        let bounds = self.worker_span.clone().unwrap_or(0..self.len());
        if offset < bounds.start
            || offset
                .checked_add(dest.len() as u64)
                .is_none_or(|end| end > bounds.end)
        {
            return Err(io::Error::other(
                "requested range is outside the pinned read span",
            ));
        }
        while !dest.is_empty() {
            if !self.cached.contains(&offset) {
                // A large bucket already owns its destination. Reading straight into
                // it avoids a second cache allocation while keeping requests bounded.
                if self.read_ahead < MAX_READ && dest.len() >= self.read_ahead {
                    let count = dest.len().min(MAX_READ);
                    let (part, remainder) = dest.split_at_mut(count);
                    Self::fetch(
                        &self.budget,
                        &self.client,
                        &self.url,
                        &self.object,
                        offset,
                        part,
                    )
                    .await?;
                    offset += count as u64;
                    dest = remainder;
                    continue;
                }
                let count = self
                    .worker_span
                    .as_ref()
                    .map_or(dest.len() as u64, |span| span.end - offset)
                    .min(self.read_ahead as u64) as usize;
                // A cancelled or failed refill must never validate partially replaced bytes.
                self.cached = 0..0;
                super::try_resize_read_buffer(&mut self.cache, count)?;
                Self::fetch(
                    &self.budget,
                    &self.client,
                    &self.url,
                    &self.object,
                    offset,
                    &mut self.cache,
                )
                .await?;
                self.cached = offset..offset + count as u64;
            }
            let cached = &self.cache[(offset - self.cached.start) as usize..];
            let n = cached.len().min(dest.len());
            dest[..n].copy_from_slice(&cached[..n]);
            offset += n as u64;
            dest = &mut dest[n..];
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;

    fn serve(response: &'static str, range: &'static str) -> (Reader, std::thread::JoinHandle<()>) {
        serve_sequence(vec![response], range)
    }

    fn serve_sequence(
        responses: Vec<&'static str>,
        range: &'static str,
    ) -> (Reader, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            for response in responses {
                let (mut socket, _) = listener.accept().unwrap();
                let mut headers = String::new();
                let mut reader = BufReader::new(&socket);
                loop {
                    let mut line = String::new();
                    assert!(reader.read_line(&mut line).unwrap() > 0);
                    if line == "\r\n" {
                        break;
                    }
                    headers.push_str(&line);
                }
                let headers = headers.to_ascii_lowercase();
                assert!(headers.starts_with("get /epoch-0.jet http/1.1\r\n"));
                assert!(headers.contains(&format!("range: {range}\r\n")));
                assert!(headers.contains("if-match: \"original\"\r\n"));
                assert!(!headers.contains("authorization:"));
                socket.write_all(response.as_bytes()).unwrap();
            }
        });
        (
            Reader {
                url: Url::parse(&format!("http://{address}/epoch-0.jet")).unwrap(),
                object: Object {
                    epoch: 0,
                    key: "epoch-0.jet".into(),
                    etag: "\"original\"".into(),
                    bytes: 8,
                },
                client: Client::new(),
                budget: Arc::new(RequestBudget::new()),
                worker_span: Some(0..8),
                cached: 0..0,
                cache: Vec::new(),
                read_ahead: MAX_READ,
            },
            handle,
        )
    }

    #[tokio::test]
    async fn resumes_the_same_pinned_range_after_three_server_errors() {
        let unavailable =
            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let recovered = "HTTP/1.1 206 Partial Content\r\nContent-Length: 8\r\nContent-Range: bytes 0-7/8\r\nETag: \"original\"\r\n\r\nabcdefgh";
        let (mut reader, server) = serve_sequence(
            vec![unavailable, unavailable, unavailable, recovered],
            "bytes=0-7",
        );
        let mut bytes = [0; 8];
        reader.read_at(0, &mut bytes).await.unwrap();
        assert_eq!(&bytes, b"abcdefgh");
        server.join().unwrap();
    }

    #[tokio::test]
    async fn verifies_headers_and_coalesces_sequential_bucket_reads() {
        let (mut reader, server) = serve(
            "HTTP/1.1 206 Partial Content\r\nContent-Length: 8\r\nContent-Range: bytes 0-7/8\r\nETag: \"original\"\r\n\r\nabcdefgh",
            "bytes=0-7",
        );
        let mut first = [0; 3];
        let mut second = [0; 5];
        reader.read_at(0, &mut first).await.unwrap();
        reader.read_at(3, &mut second).await.unwrap();
        assert_eq!(&first, b"abc");
        assert_eq!(&second, b"defgh");
        server.join().unwrap();
    }

    #[test]
    fn wide_audits_bound_aggregate_http_cache() {
        assert_eq!(read_ahead(4), MAX_READ);
        assert_eq!(read_ahead(256), 2 << 20);
        assert!(read_ahead(256) * 256 <= TOTAL_READ_AHEAD);
    }

    #[test]
    fn retry_after_applies_to_all_readers_without_shortening_existing_delay() {
        let budget = RequestBudget::new();
        let start = Instant::now();
        budget
            .defer(Some(&header::HeaderValue::from_static("30")), 0)
            .unwrap();
        let first = *budget.resume.lock().unwrap();
        assert!(first >= start + Duration::from_secs(30));
        budget
            .defer(Some(&header::HeaderValue::from_static("0")), 0)
            .unwrap();
        assert_eq!(first, *budget.resume.lock().unwrap());
        let date = httpdate::fmt_http_date(SystemTime::now() + Duration::from_secs(60));
        budget
            .defer(Some(&header::HeaderValue::from_str(&date).unwrap()), 0)
            .unwrap();
        assert!(*budget.resume.lock().unwrap() > first);
        assert!(
            budget
                .defer(Some(&header::HeaderValue::from_static("500")), 0)
                .is_err()
        );
    }

    #[tokio::test]
    async fn wide_reader_reads_large_bucket_directly_without_a_second_buffer() {
        let (mut reader, server) = serve(
            "HTTP/1.1 206 Partial Content\r\nContent-Length: 8\r\nContent-Range: bytes 0-7/8\r\nETag: \"original\"\r\n\r\nabcdefgh",
            "bytes=0-7",
        );
        reader.read_ahead = 4;
        let mut bytes = [0; 8];
        reader.read_at(0, &mut bytes).await.unwrap();
        assert_eq!(&bytes, b"abcdefgh");
        assert_eq!(reader.cache.capacity(), 0);
        server.join().unwrap();
    }

    #[tokio::test]
    async fn compact_cache_coalesces_small_reads_to_its_worker_budget() {
        let (mut reader, server) = serve(
            "HTTP/1.1 206 Partial Content\r\nContent-Length: 4\r\nContent-Range: bytes 0-3/8\r\nETag: \"original\"\r\n\r\nabcd",
            "bytes=0-3",
        );
        reader.read_ahead = 4;
        let mut bytes = [0; 2];
        reader.read_at(0, &mut bytes).await.unwrap();
        assert_eq!(&bytes, b"ab");
        reader.read_at(2, &mut bytes).await.unwrap();
        assert_eq!(&bytes, b"cd");
        assert_eq!(reader.cache.len(), 4);
        server.join().unwrap();
    }

    #[tokio::test]
    async fn adjacent_workers_do_not_prefetch_each_others_buckets() {
        let (mut reader, server) = serve(
            "HTTP/1.1 206 Partial Content\r\nContent-Length: 4\r\nContent-Range: bytes 3-6/12\r\nETag: \"original\"\r\n\r\ndefg",
            "bytes=3-6",
        );
        reader.object.bytes = 12;
        reader.worker_span = Some(3..7);
        // Reject either neighbor before opening the worker's only request.
        assert!(reader.read_at(2, &mut [0]).await.is_err());
        assert!(reader.read_at(6, &mut [0; 2]).await.is_err());
        let mut first = [0];
        let mut rest = [0; 3];
        reader.read_at(3, &mut first).await.unwrap();
        reader.read_at(4, &mut rest).await.unwrap();
        assert_eq!(&first, b"d");
        assert_eq!(&rest, b"efg");
        server.join().unwrap();
    }

    #[tokio::test]
    async fn rejects_unconditional_or_wrong_generation_and_bounds() {
        for response in [
            "HTTP/1.1 200 OK\r\nContent-Length: 8\r\nETag: \"original\"\r\n\r\nabcdefgh",
            "HTTP/1.1 206 Partial Content\r\nContent-Length: 8\r\nContent-Range: bytes 0-7/8\r\nETag: \"replacement\"\r\n\r\nabcdefgh",
            "HTTP/1.1 206 Partial Content\r\nContent-Length: 8\r\nContent-Range: bytes 0-7/9\r\nETag: \"original\"\r\n\r\nabcdefgh",
        ] {
            let (mut reader, server) = serve(response, "bytes=0-7");
            let mut bytes = [0; 8];
            assert!(reader.read_at(0, &mut bytes).await.is_err());
            assert_eq!(bytes, [0; 8]);
            server.join().unwrap();
        }
    }
}
