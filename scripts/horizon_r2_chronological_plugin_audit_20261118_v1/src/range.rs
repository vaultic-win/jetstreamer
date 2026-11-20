//! Sequential conditional range reads. No range retries or cross-attempt resume.
use crate::remote::{TransferIdentity, TransferInterruption, TransferInterruptionKind};
use anyhow::{Context, Result, ensure};
use aws_sdk_s3::{
    Client,
    config::{
        ConfigBag, Intercept, RuntimeComponents,
        interceptors::BeforeDeserializationInterceptorContextRef, retry::RetryConfig,
    },
    error::BoxError,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{error::Error, time::Duration};
use tokio::time::Instant;

pub const RANGE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Serialize)]
pub struct TransferPlan<'a> {
    schema: &'static str,
    identity: &'a TransferIdentity,
    range_bytes: u64,
    range_count: u64,
    total_bytes: u64,
    concurrency: u32,
    range_retries: u32,
    whole_file_verified: bool,
    playback_completed: bool,
}
pub fn plan(identity: &TransferIdentity) -> Result<TransferPlan<'_>> {
    ensure!(identity.object.bytes > 0, "empty archive transfer");
    Ok(TransferPlan {
        schema: "horizon-r2-audit-range-transfer-plan-v1",
        identity,
        range_bytes: RANGE_BYTES,
        range_count: identity.object.bytes.div_ceil(RANGE_BYTES),
        total_bytes: identity.object.bytes,
        concurrency: 1,
        range_retries: 0,
        whole_file_verified: false,
        playback_completed: false,
    })
}

#[derive(Clone, Copy, Debug)]
struct Span {
    start: u64,
    end: u64, // exclusive
    total: u64,
}
impl Span {
    fn next(start: u64, total: u64, limit: u64) -> Result<Self> {
        ensure!(
            start < total && (1..=RANGE_BYTES).contains(&limit),
            "invalid range bounds"
        );
        let length = (total - start).min(limit);
        Ok(Self {
            start,
            end: start.checked_add(length).context("range overflow")?,
            total,
        })
    }
    fn length(self) -> u64 {
        self.end - self.start
    }
    fn request(self) -> String {
        format!("bytes={}-{}", self.start, self.end - 1)
    }
    fn response(self) -> String {
        format!("bytes {}-{}/{}", self.start, self.end - 1, self.total)
    }
}

/// GetObjectOutput does not expose raw HTTP status. Validate it before SDK
/// deserialization; plausible Content-Range on an HTTP200 must never pass.
#[derive(Debug)]
struct ExactRangeResponse {
    span: Span,
    identity: TransferIdentity,
}
impl Intercept for ExactRangeResponse {
    fn name(&self) -> &'static str {
        "horizon-audit-exact-range-response"
    }
    fn read_before_deserialization(
        &self,
        context: &BeforeDeserializationInterceptorContextRef<'_>,
        _runtime: &RuntimeComponents,
        _config: &mut ConfigBag,
    ) -> std::result::Result<(), BoxError> {
        let response = context.response();
        let check: Result<()> = (|| {
            ensure!(
                response.status().as_u16() == 206,
                "range GET requires HTTP206; received HTTP{} for {} of {} bytes",
                response.status().as_u16(),
                self.span.request(),
                self.span.total
            );
            let headers = response.headers();
            for (key, expected) in [
                ("content-range", Some(self.span.response())),
                ("content-length", Some(self.span.length().to_string())),
                ("etag", Some(self.identity.object.etag.clone())),
                ("x-amz-version-id", self.identity.version_id.clone()),
                ("x-amz-meta-sha256", self.identity.metadata_sha256.clone()),
            ] {
                let mut values = headers.get_all(key);
                ensure!(
                    values.next() == expected.as_deref() && values.next().is_none(),
                    "range response {key} differs or is duplicated"
                );
            }
            let mut encoding = headers.get_all("content-encoding");
            ensure!(
                matches!(encoding.next(), None | Some("identity")) && encoding.next().is_none(),
                "encoded range response"
            );
            ensure!(
                headers.get_all("transfer-encoding").next().is_none(),
                "range response lacks fixed framing"
            );
            ensure!(
                headers
                    .get_all("content-type")
                    .all(|value| !value.to_ascii_lowercase().starts_with("multipart/")),
                "multipart range response"
            );
            Ok(())
        })();
        check.map_err(Into::into)
    }
}

fn error_chain(error: &(dyn Error + 'static)) -> String {
    let mut detail = String::new();
    let mut current = Some(error);
    for _ in 0..8 {
        let Some(error) = current else { break };
        if !detail.is_empty() {
            if detail.len() > 8190 {
                return detail;
            }
            detail.push_str(": ");
        }
        for character in error.to_string().chars() {
            if detail.len() + character.len_utf8() > 8192 {
                return detail;
            }
            detail.push(character);
        }
        current = error.source();
    }
    detail
}
fn require_time(deadline: Instant) -> Result<()> {
    ensure!(
        Instant::now() < deadline,
        "archive download deadline exceeded"
    );
    Ok(())
}
fn check_body_length(actual: u64, span: Span) -> Result<()> {
    ensure!(
        actual == span.length(),
        "range body length differs: {actual} != {}",
        span.length()
    );
    Ok(())
}
async fn read_range(
    client: &Client,
    identity: &TransferIdentity,
    span: Span,
    deadline: Instant,
    read_timeout: Duration,
) -> Result<Vec<u8>> {
    require_time(deadline)?;
    let request = client
        .get_object()
        .bucket(&identity.bucket)
        .key(&identity.object.key)
        .if_match(&identity.object.etag)
        .set_version_id(identity.version_id.clone())
        .range(span.request())
        .customize()
        .config_override(
            aws_sdk_s3::config::Builder::new()
                .retry_config(RetryConfig::standard().with_max_attempts(1)),
        )
        .interceptor(ExactRangeResponse {
            span,
            identity: identity.clone(),
        });
    let mut response = tokio::time::timeout_at(deadline, request.send())
        .await
        .context("archive download deadline exceeded during range GET")?
        .context("GET exact pinned archive range")?;
    // Retain modeled-output checks as well as the raw response interceptor.
    ensure!(
        response.content_range() == Some(span.response().as_str())
            && response
                .content_length()
                .and_then(|value| u64::try_from(value).ok())
                == Some(span.length())
            && response.e_tag() == Some(identity.object.etag.as_str())
            && response.version_id() == identity.version_id.as_deref()
            && response
                .metadata()
                .and_then(|metadata| metadata.get("sha256"))
                .map(String::as_str)
                == identity.metadata_sha256.as_deref(),
        "modeled range identity or bounds differ"
    );
    let mut buffer = Vec::new();
    buffer.try_reserve_exact(usize::try_from(span.length())?)?;
    loop {
        require_time(deadline)?;
        let idle_deadline = Instant::now()
            .checked_add(read_timeout)
            .context("read timeout overflow")?;
        let next =
            tokio::time::timeout_at(deadline.min(idle_deadline), response.body.try_next()).await;
        require_time(deadline)?;
        let downloaded = span
            .start
            .checked_add(u64::try_from(buffer.len())?)
            .context("download count overflow")?;
        let next = match next {
            Ok(Ok(next)) => next,
            Ok(Err(error)) => {
                return Err(TransferInterruption {
                    kind: TransferInterruptionKind::BodyReadError,
                    identity: identity.clone(),
                    downloaded_bytes: downloaded,
                    detail: error_chain(&error),
                }
                .into());
            }
            Err(error) => {
                // An exhausted whole-download deadline is not an idle transport
                // timeout and cannot acquire another outer transport retry.
                require_time(deadline)?;
                return Err(TransferInterruption {
                    kind: TransferInterruptionKind::BodyReadTimeout,
                    identity: identity.clone(),
                    downloaded_bytes: downloaded,
                    detail: error.to_string(),
                }
                .into());
            }
        };
        let Some(bytes) = next else { break };
        let next_length = u64::try_from(buffer.len())?
            .checked_add(u64::try_from(bytes.len())?)
            .context("range body overflow")?;
        ensure!(
            next_length <= span.length(),
            "range body exceeds declared length"
        );
        buffer.extend_from_slice(&bytes);
    }
    require_time(deadline)?;
    check_body_length(u64::try_from(buffer.len())?, span)?;
    Ok(buffer)
}

pub async fn transfer<F>(
    client: &Client,
    identity: &TransferIdentity,
    deadline: Instant,
    read_timeout: Duration,
    append: F,
) -> Result<(u64, String)>
where
    F: FnMut(u64, &[u8]) -> Result<()>,
{
    transfer_bounded(
        client,
        identity,
        deadline,
        read_timeout,
        RANGE_BYTES,
        append,
    )
    .await
}
async fn transfer_bounded<F>(
    client: &Client,
    identity: &TransferIdentity,
    deadline: Instant,
    read_timeout: Duration,
    range_bytes: u64,
    mut append: F,
) -> Result<(u64, String)>
where
    F: FnMut(u64, &[u8]) -> Result<()>,
{
    ensure!(
        identity.object.bytes > 0 && !read_timeout.is_zero(),
        "invalid transfer bounds"
    );
    let mut committed = 0;
    let mut hash = Sha256::new();
    while committed < identity.object.bytes {
        let span = Span::next(committed, identity.object.bytes, range_bytes)?;
        let bytes = read_range(client, identity, span, deadline, read_timeout).await?;
        require_time(deadline)?;
        append(committed, &bytes)?;
        hash.update(&bytes);
        committed = span.end;
        require_time(deadline)?;
    }
    Ok((committed, format!("{:x}", hash.finalize())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::Object;
    use aws_credential_types::{Credentials, provider::SharedCredentialsProvider};
    use aws_sdk_s3::config::{BehaviorVersion, Region};
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    fn identity(total: u64) -> TransferIdentity {
        TransferIdentity {
            bucket: "fixture".into(),
            object: Object {
                epoch: 79,
                key: "epoch-79.jet".into(),
                etag: "\"fixture\"".into(),
                bytes: total,
            },
            version_id: Some("version-1".into()),
            metadata_sha256: None,
            sidecar_sha256: Some("a".repeat(64)),
            sidecar_etag: Some("\"sidecar\"".into()),
        }
    }
    fn client(endpoint: &str) -> Client {
        Client::from_conf(
            aws_sdk_s3::config::Builder::new()
                .behavior_version(BehaviorVersion::latest())
                .region(Region::new("auto"))
                .credentials_provider(SharedCredentialsProvider::new(Credentials::new(
                    "fixture", "fixture", None, None, "fixture",
                )))
                .endpoint_url(endpoint)
                .force_path_style(true)
                .retry_config(RetryConfig::standard().with_max_attempts(1))
                .build(),
        )
    }
    fn serve(replies: Vec<(Span, Vec<u8>)>) -> (Client, thread::JoinHandle<()>) {
        serve_delayed(replies, Duration::ZERO)
    }
    fn serve_delayed(
        replies: Vec<(Span, Vec<u8>)>,
        body_delay: Duration,
    ) -> (Client, thread::JoinHandle<()>) {
        serve_with_version(replies, body_delay, true)
    }
    fn serve_with_version(
        replies: Vec<(Span, Vec<u8>)>,
        body_delay: Duration,
        versioned: bool,
    ) -> (Client, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let task = thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            for (span, reply) in replies {
                let mut connection = loop {
                    match listener.accept() {
                        Ok((connection, _)) => break connection,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                std::time::Instant::now() < deadline,
                                "range fixture request missing"
                            );
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("fixture accept: {error}"),
                    }
                };
                connection
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                connection
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut headers = Vec::new();
                while !headers.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    connection.read_exact(&mut byte).unwrap();
                    headers.push(byte[0]);
                    assert!(headers.len() < 16384);
                }
                let request = String::from_utf8(headers).unwrap();
                let lower = request.to_ascii_lowercase();
                assert!(lower.starts_with("get /fixture/epoch-79.jet"));
                assert_eq!(
                    lower
                        .lines()
                        .next()
                        .unwrap()
                        .contains("versionid=version-1"),
                    versioned
                );
                assert!(lower.contains(&format!("range: {}\r\n", span.request())));
                assert!(lower.contains("if-match: \"fixture\"\r\n"));
                // A rejecting header interceptor may close before body writes.
                let header_end = reply
                    .windows(4)
                    .position(|bytes| bytes == b"\r\n\r\n")
                    .unwrap()
                    + 4;
                let _ = connection.write_all(&reply[..header_end]);
                if !body_delay.is_zero() {
                    thread::sleep(body_delay);
                }
                let _ = connection.write_all(&reply[header_end..]);
            }
        });
        (client(&endpoint), task)
    }
    fn reply(span: Span, body: &[u8]) -> Vec<u8> {
        let mut wire = format!("HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: {}\r\nETag: \"fixture\"\r\nx-amz-version-id: version-1\r\nConnection: close\r\n\r\n", span.length(), span.response()).into_bytes();
        wire.extend_from_slice(body);
        wire
    }
    #[test]
    fn plan_and_spans_are_bounded_contiguous_and_overflow_safe() {
        let identity = identity(22_488_198_990);
        let plan = plan(&identity).unwrap();
        assert_eq!(plan.range_count, 336);
        let mut start = 0;
        let mut ranges = 0;
        while start < identity.object.bytes {
            let span = Span::next(start, identity.object.bytes, RANGE_BYTES).unwrap();
            assert!(span.length() <= RANGE_BYTES && span.start == start);
            start = span.end;
            ranges += 1;
        }
        assert_eq!(ranges, plan.range_count);
        assert_eq!(
            Span::next(u64::MAX - 1, u64::MAX, RANGE_BYTES)
                .unwrap()
                .length(),
            1
        );
        assert!(Span::next(0, 0, RANGE_BYTES).is_err());
        assert!(Span::next(0, 1, 0).is_err());
        assert!(Span::next(0, 1, RANGE_BYTES + 1).is_err());
    }
    #[tokio::test]
    async fn actual_http_range_path_appends_contiguously_and_hashes_whole_file() {
        let identity = identity(8);
        let spans = [
            Span::next(0, 8, 3).unwrap(),
            Span::next(3, 8, 3).unwrap(),
            Span::next(6, 8, 3).unwrap(),
        ];
        let body = b"abcdefgh";
        let replies = spans
            .iter()
            .map(|span| {
                (
                    *span,
                    reply(*span, &body[span.start as usize..span.end as usize]),
                )
            })
            .collect();
        let (client, server) = serve(replies);
        let mut written = Vec::new();
        let result = transfer_bounded(
            &client,
            &identity,
            Instant::now() + Duration::from_secs(10),
            Duration::from_secs(2),
            3,
            |start, bytes| {
                ensure!(start == written.len() as u64, "noncontiguous write");
                written.extend_from_slice(bytes);
                Ok(())
            },
        )
        .await;
        server.join().unwrap();
        let (count, digest) = result.unwrap();
        assert_eq!(written, body);
        assert_eq!(count, 8);
        assert_eq!(digest, format!("{:x}", Sha256::digest(body)));
    }
    #[tokio::test]
    async fn actual_http_rejects_wrong_status_ranges_and_identity_before_append() {
        let span = Span::next(0, 3, 3).unwrap();
        let good = String::from_utf8(reply(span, b"abc")).unwrap();
        let bad = [
            good.replace("206 Partial Content", "200 OK"),
            good.replace("206 Partial Content", "416 Range Not Satisfiable"),
            good.replace("Content-Range: bytes 0-2/3\r\n", ""),
            good.replace("bytes 0-2/3", "bytes 1-3/3"),
            good.replace("bytes 0-2/3", "bytes 0-3/3"),
            good.replace("bytes 0-2/3", "bytes 0-2/4"),
            good.replace("bytes 0-2/3", "bytes 0-2/*"),
            good.replace("bytes 0-2/3", "bytes 0-2/3, 0-2/3"),
            good.replace("Content-Length: 3", "Content-Length: 4"),
            good.replace("Content-Length: 3", "Content-Length: 2"),
            good.replace("Content-Length: 3\r\n", ""),
            good.replace("ETag: \"fixture\"\r\n", ""),
            good.replace("ETag: \"fixture\"", "ETag: \"changed\""),
            good.replace("version-1", "version-2"),
            good.replace("x-amz-version-id: version-1\r\n", ""),
            good.replace(
                "Connection: close",
                "Content-Encoding: gzip\r\nConnection: close",
            ),
            good.replace(
                "Content-Range: bytes 0-2/3",
                "Content-Range: bytes 0-2/3\r\nContent-Range: bytes 0-2/3",
            ),
        ];
        for wire in bad {
            let (client, server) = serve(vec![(span, wire.into_bytes())]);
            let mut writes = 0;
            let result = transfer_bounded(
                &client,
                &identity(3),
                Instant::now() + Duration::from_secs(10),
                Duration::from_secs(2),
                3,
                |_, _| {
                    writes += 1;
                    Ok(())
                },
            )
            .await;
            server.join().unwrap();
            assert!(result.is_err());
            assert_eq!(writes, 0);
            assert!(
                result
                    .unwrap_err()
                    .downcast_ref::<TransferInterruption>()
                    .is_none()
            );
        }
    }
    #[tokio::test]
    async fn unversioned_r2_identity_stays_unversioned() {
        let span = Span::next(0, 3, 3).unwrap();
        for unexpected_version in [false, true] {
            let wire = String::from_utf8(reply(span, b"abc")).unwrap();
            let wire = if unexpected_version {
                wire
            } else {
                wire.replace("x-amz-version-id: version-1\r\n", "")
            };
            let (client, server) =
                serve_with_version(vec![(span, wire.into_bytes())], Duration::ZERO, false);
            let mut identity = identity(3);
            identity.version_id = None;
            let mut written = Vec::new();
            let result = transfer_bounded(
                &client,
                &identity,
                Instant::now() + Duration::from_secs(10),
                Duration::from_secs(2),
                3,
                |_, bytes| {
                    written.extend_from_slice(bytes);
                    Ok(())
                },
            )
            .await;
            server.join().unwrap();
            if unexpected_version {
                assert!(result.is_err());
                assert!(written.is_empty());
            } else {
                assert_eq!(result.unwrap().0, 3);
                assert_eq!(written, b"abc");
            }
        }
    }
    #[tokio::test]
    async fn interrupted_response_never_appends_partial_range_or_retries_it() {
        let span = Span::next(0, 3, 3).unwrap();
        let (client, server) = serve(vec![(span, reply(span, b"ab"))]);
        let mut writes = 0;
        let error = transfer_bounded(
            &client,
            &identity(3),
            Instant::now() + Duration::from_secs(10),
            Duration::from_secs(2),
            3,
            |_, _| {
                writes += 1;
                Ok(())
            },
        )
        .await
        .unwrap_err();
        server.join().unwrap();
        assert_eq!(writes, 0);
        assert_eq!(
            error.downcast_ref::<TransferInterruption>().unwrap().kind,
            TransferInterruptionKind::BodyReadError
        );
    }
    #[tokio::test]
    async fn later_interrupted_range_preserves_only_completed_prefix() {
        let first = Span::next(0, 6, 3).unwrap();
        let second = Span::next(3, 6, 3).unwrap();
        let (client, server) = serve(vec![
            (first, reply(first, b"abc")),
            (second, reply(second, b"de")),
        ]);
        let mut written = Vec::new();
        let error = transfer_bounded(
            &client,
            &identity(6),
            Instant::now() + Duration::from_secs(10),
            Duration::from_secs(2),
            3,
            |start, bytes| {
                ensure!(start == written.len() as u64, "noncontiguous append");
                written.extend_from_slice(bytes);
                Ok(())
            },
        )
        .await
        .unwrap_err();
        server.join().unwrap();
        assert_eq!(written, b"abc");
        let failure = error.downcast_ref::<TransferInterruption>().unwrap();
        assert_eq!(failure.kind, TransferInterruptionKind::BodyReadError);
        assert!((3..6).contains(&failure.downloaded_bytes));
    }
    #[tokio::test]
    async fn body_idle_timeout_is_typed_but_absolute_deadline_is_not() {
        for overall in [false, true] {
            let span = Span::next(0, 3, 3).unwrap();
            let (client, server) = serve_delayed(
                vec![(span, reply(span, b"abc"))],
                Duration::from_millis(1500),
            );
            let deadline = Instant::now()
                + if overall {
                    Duration::from_secs(1)
                } else {
                    Duration::from_secs(10)
                };
            let idle = if overall {
                Duration::from_secs(2)
            } else {
                Duration::from_millis(25)
            };
            let error = transfer_bounded(&client, &identity(3), deadline, idle, 3, |_, _| {
                panic!("timed out response appended")
            })
            .await
            .unwrap_err();
            server.join().unwrap();
            if overall {
                assert!(error.downcast_ref::<TransferInterruption>().is_none());
            } else {
                assert_eq!(
                    error.downcast_ref::<TransferInterruption>().unwrap().kind,
                    TransferInterruptionKind::BodyReadTimeout
                );
            }
        }
    }
    #[tokio::test]
    async fn expired_overall_deadline_and_writer_failure_are_not_transport_retries() {
        let client = client("http://127.0.0.1:1");
        let error = transfer(
            &client,
            &identity(3),
            Instant::now() - Duration::from_secs(1),
            Duration::from_secs(1),
            |_, _| panic!("unexpected write"),
        )
        .await
        .unwrap_err();
        assert!(error.downcast_ref::<TransferInterruption>().is_none());
        let span = Span::next(0, 3, 3).unwrap();
        let (client, server) = serve(vec![(span, reply(span, b"abc"))]);
        let error = transfer_bounded(
            &client,
            &identity(3),
            Instant::now() + Duration::from_secs(10),
            Duration::from_secs(2),
            3,
            |_, _| anyhow::bail!("fixture disk guard"),
        )
        .await
        .unwrap_err();
        server.join().unwrap();
        assert!(error.downcast_ref::<TransferInterruption>().is_none());
        assert!(error.to_string().contains("fixture disk guard"));
        assert!(check_body_length(2, span).is_err());
        assert!(check_body_length(4, span).is_err());
    }
}
