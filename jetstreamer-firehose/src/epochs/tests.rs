use super::*;
use serde_json::{Value, json};
use std::{borrow::Cow, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
    time::timeout,
};

struct Reply {
    request_line: Cow<'static, str>,
    range: Option<String>,
    request_json: Option<Value>,
    status: &'static str,
    headers: String,
    body: Vec<u8>,
}

impl Reply {
    fn head(request_line: impl Into<Cow<'static, str>>, status: &'static str) -> Self {
        Self {
            request_line: request_line.into(),
            range: None,
            request_json: None,
            status,
            headers: String::new(),
            body: Vec::new(),
        }
    }

    fn range(start: usize, end: usize, bytes: &[u8]) -> Self {
        Self {
            request_line: "GET /archive/670/epoch-670.car HTTP/1.1".into(),
            range: Some(format!("bytes={start}-{end}")),
            request_json: None,
            status: "206 Partial Content",
            headers: format!("Content-Range: bytes {start}-{end}/{}\r\n", bytes.len()),
            body: bytes[start..=end].to_vec(),
        }
    }

    fn rpc(response: Value) -> Self {
        Self {
            request_line: "POST /archive/ HTTP/1.1".into(),
            range: None,
            request_json: Some(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getBlock",
                "params": [246446651, { "maxSupportedTransactionVersion": 0 }],
            })),
            status: "200 OK",
            headers: "Content-Type: application/json\r\n".into(),
            body: serde_json::to_vec(&response).unwrap(),
        }
    }
}

struct TestServer {
    url: reqwest::Url,
    task: Option<JoinHandle<()>>,
}

impl TestServer {
    async fn start(replies: Vec<Reply>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/archive/", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let task = tokio::spawn(async move {
            timeout(Duration::from_secs(10), async move {
                for reply in replies {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let mut request = Vec::new();
                    while !request.ends_with(b"\r\n\r\n") {
                        assert!(request.len() < 16 * 1024, "request headers are too large");
                        request.push(socket.read_u8().await.unwrap());
                    }
                    let headers = std::str::from_utf8(&request).unwrap();
                    assert_eq!(headers.lines().next().unwrap(), reply.request_line);
                    let header = |name: &str| {
                        headers.lines().skip(1).find_map(|line| {
                            let (key, value) = line.split_once(':')?;
                            key.eq_ignore_ascii_case(name).then_some(value.trim())
                        })
                    };
                    assert_eq!(header("range"), reply.range.as_deref());
                    let body_len = header("content-length")
                        .map(|len| len.parse::<usize>().unwrap())
                        .unwrap_or(0);
                    assert!(body_len <= 4096, "request body is too large");
                    let mut body = vec![0; body_len];
                    socket.read_exact(&mut body).await.unwrap();
                    if let Some(expected) = reply.request_json {
                        assert_eq!(serde_json::from_slice::<Value>(&body).unwrap(), expected);
                    } else {
                        assert!(body.is_empty());
                    }
                    let mut response = format!(
                        "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n{}\r\n",
                        reply.status,
                        reply.body.len(),
                        reply.headers,
                    )
                    .into_bytes();
                    response.extend_from_slice(&reply.body);
                    socket.write_all(&response).await.unwrap();
                    socket.shutdown().await.unwrap();
                }
            })
            .await
            .expect("local HTTP fixture timed out");
        });
        Self {
            url,
            task: Some(task),
        }
    }

    fn location(&self) -> archive::Location {
        archive::Location::http(self.url.clone())
    }

    async fn finish(mut self) {
        self.task.take().unwrap().await.unwrap();
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

fn client() -> Client {
    Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

#[tokio::test]
async fn test_fetch_epoch_stream() {
    let bytes: Vec<_> = (0..4096).map(|offset| (offset % 251) as u8).collect();
    let server = TestServer::start(vec![
        Reply::range(0, 0, &bytes),
        Reply::range(0, 4095, &bytes),
        Reply::range(3072, 4095, &bytes),
    ])
    .await;
    let mut stream = fetch_epoch_stream_at(670, &client(), None, &server.location()).await;
    assert_eq!(stream.len(), bytes.len() as u64);

    let mut buf = [0; 1024];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(buf, bytes[..1024]);

    assert_eq!(stream.seek(SeekFrom::End(-1024)).await.unwrap(), 3072);
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(buf, bytes[3072..]);
    server.finish().await;
}

#[tokio::test]
async fn test_epoch_exists() {
    let server = TestServer::start(vec![
        Reply::head("HEAD /archive/670/epoch-670.car HTTP/1.1", "200 OK"),
        Reply::head(
            "HEAD /archive/999999/epoch-999999.car HTTP/1.1",
            "404 Not Found",
        ),
        Reply::head(
            "HEAD /archive/670/epoch-670.car HTTP/1.1",
            "503 Service Unavailable",
        ),
    ])
    .await;
    let client = client();
    let location = server.location();
    assert!(epoch_exists_at(670, &client, &location).await);
    assert!(!epoch_exists_at(999999, &client, &location).await);
    assert!(!epoch_exists_at(670, &client, &location).await);
    server.finish().await;
}

const FAST_RETRY: Duration = Duration::from_millis(1);

fn head(epoch: u64, status: &'static str) -> Reply {
    Reply::head(
        format!("HEAD /archive/{epoch}/epoch-{epoch}.car HTTP/1.1"),
        status,
    )
}

#[tokio::test]
async fn test_check_epoch_exists_separates_missing_from_failed() {
    let server = TestServer::start(vec![
        head(670, "200 OK"),
        head(671, "404 Not Found"),
        head(670, "429 Too Many Requests"),
        head(670, "503 Service Unavailable"),
    ])
    .await;
    let (client, location) = (client(), server.location());
    assert!(
        check_epoch_exists_at(670, &client, &location)
            .await
            .unwrap()
    );
    assert!(
        !check_epoch_exists_at(671, &client, &location)
            .await
            .unwrap()
    );
    assert!(
        check_epoch_exists_at(670, &client, &location)
            .await
            .is_err()
    );
    assert!(
        check_epoch_exists_at(670, &client, &location)
            .await
            .is_err()
    );
    server.finish().await;
}

#[tokio::test]
async fn test_latest_epoch_walks_down_past_missing_epochs() {
    let server = TestServer::start(vec![
        head(672, "404 Not Found"),
        head(671, "404 Not Found"),
        head(670, "200 OK"),
    ])
    .await;
    let epoch = latest_epoch_at(672, &client(), &server.location(), FAST_RETRY).await;
    assert_eq!(epoch.unwrap(), 670);
    server.finish().await;
}

#[tokio::test]
async fn test_latest_epoch_retries_a_throttled_check() {
    let server = TestServer::start(vec![
        head(670, "429 Too Many Requests"),
        head(670, "200 OK"),
    ])
    .await;
    let epoch = latest_epoch_at(670, &client(), &server.location(), FAST_RETRY).await;
    assert_eq!(epoch.unwrap(), 670);
    server.finish().await;
}

#[tokio::test]
async fn test_latest_epoch_does_not_walk_past_persistent_throttling() {
    let server =
        TestServer::start((0..5).map(|_| head(670, "429 Too Many Requests")).collect()).await;
    let err = latest_epoch_at(670, &client(), &server.location(), FAST_RETRY)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("429"), "unexpected error: {err}");
    server.finish().await;
}

#[tokio::test]
async fn test_latest_epoch_stops_at_epoch_zero() {
    let server = TestServer::start(vec![head(1, "404 Not Found"), head(0, "404 Not Found")]).await;
    let err = latest_epoch_at(1, &client(), &server.location(), FAST_RETRY)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("no Old Faithful epoch"),
        "unexpected error: {err}"
    );
    server.finish().await;
}

#[tokio::test]
async fn test_get_slot_timestamp() {
    let server = TestServer::start(vec![Reply::rpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": { "blockTime": 1712000000 },
    }))])
    .await;
    let timestamp = get_slot_timestamp(246446651, server.url.as_str(), &client())
        .await
        .unwrap();
    assert_eq!(timestamp, 1712000000);
    server.finish().await;
}

#[tokio::test]
async fn test_get_slot_timestamp_rpc_errors() {
    let error = json!({ "code": -32007, "message": "Slot was skipped" });
    let server = TestServer::start(vec![
        Reply::rpc(json!({ "result": null })),
        Reply::rpc(json!({ "error": error })),
    ])
    .await;
    let client = client();
    assert!(matches!(
        get_slot_timestamp(246446651, server.url.as_str(), &client).await,
        Err(SlotTimestampError::NoBlockTime)
    ));
    match get_slot_timestamp(246446651, server.url.as_str(), &client).await {
        Err(SlotTimestampError::Rpc(Some(actual))) => assert_eq!(actual, error),
        other => panic!("expected RPC error, got {other:?}"),
    }
    server.finish().await;
}
