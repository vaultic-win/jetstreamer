//! Local TLS controls over the production head/get functions and client policy.
//! Enable native-transport-tests and run as root in the private network sandbox.
use super::*;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::{
    fs,
    net::TcpListener,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Server {
    url: String,
    task: JoinHandle<String>,
}

impl Server {
    fn start(response: Vec<u8>, linger: Duration) -> Self {
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(
                include_bytes!("../native-fixtures/server.der").to_vec(),
            )],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                include_bytes!("../native-fixtures/test-key.der").to_vec(),
            )),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!(
            "https://127.0.0.1:{}/object",
            listener.local_addr().unwrap().port()
        );
        let task = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let connection = rustls::ServerConnection::new(Arc::new(config)).unwrap();
            let mut stream = rustls::StreamOwned::new(connection, socket);
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                match stream.read(&mut byte) {
                    Ok(1) => request.push(byte[0]),
                    other => return format!("TLS/request rejected: {other:?}"),
                }
                assert!(request.len() <= 16384);
            }
            // Rejection can close TLS before the server finishes its response.
            let _ = stream.write_all(&response);
            let _ = stream.flush();
            thread::sleep(linger);
            String::from_utf8(request).unwrap()
        });
        Self { url, task }
    }

    fn finish(self) -> String {
        self.task.join().unwrap()
    }
}

fn output() -> Output {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "native custody tests require root"
    );
    let parent = std::env::temp_dir().join(format!(
        "epoch168-native-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed),
    ));
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, Permissions::from_mode(0o700)).unwrap();
    Output::create(&parent.join("capture")).unwrap()
}

fn client() -> Client {
    client_builder()
        .tls_certs_merge([reqwest::Certificate::from_der(include_bytes!(
            "../native-fixtures/ca.der"
        ))
        .unwrap()])
        .build()
        .unwrap()
}

fn deadline(duration: Duration) -> Deadline {
    Deadline {
        unix_millis: now().unwrap() + u64::try_from(duration.as_millis()).unwrap(),
        monotonic: Instant::now() + duration,
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn representation_fixture() -> Representation {
    Representation {
        etag: "\"version-a\"".into(),
        length: 1000,
        version: BTreeMap::new(),
    }
}

fn response(status: u16, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut bytes = format!("HTTP/1.1 {status} Fixture\r\nConnection: close\r\n").into_bytes();
    for (key, value) in headers {
        bytes.extend_from_slice(format!("{key}: {value}\r\n").as_bytes());
    }
    bytes.extend_from_slice(b"\r\n");
    bytes.extend_from_slice(body);
    bytes
}

fn good_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        ("ETag", "\"version-a\""),
        ("Content-Length", "10"),
        ("Content-Range", "bytes 100-109/1000"),
    ]
}

fn rejected_range(wire: Vec<u8>) -> String {
    let server = Server::start(wire, Duration::ZERO);
    let mut out = output();
    let error = runtime()
        .block_on(get(
            &client(),
            &mut out,
            "range",
            &server.url,
            &representation_fixture(),
            (100, 10),
            deadline(Duration::from_secs(5)),
        ))
        .unwrap_err()
        .to_string();
    let request = server.finish();
    assert!(request.starts_with("GET /object HTTP/1.1\r\n"), "{request}");
    assert!(!out.path.join("completion.json").exists());
    assert!(!out.path.join("COMPLETION.sha256").exists());
    error
}

#[test]
fn tls_range_preserves_exact_bytes_conditional_headers_and_private_custody() {
    let server = Server::start(
        response(206, &good_headers(), b"0123456789"),
        Duration::ZERO,
    );
    let mut out = output();
    let bytes = runtime()
        .block_on(get(
            &client(),
            &mut out,
            "range",
            &server.url,
            &representation_fixture(),
            (100, 10),
            deadline(Duration::from_secs(5)),
        ))
        .unwrap();
    assert_eq!(bytes, b"0123456789");
    assert_eq!(fs::read(out.path.join("range.bin")).unwrap(), bytes);
    assert_eq!(out.members["range.bin"]["sha256"], hash(&bytes));
    let file = fs::metadata(out.path.join("range.bin")).unwrap();
    assert_eq!(
        (file.uid(), file.mode() & 0o777, file.nlink()),
        (0, 0o400, 1)
    );
    let directory = fs::metadata(&out.path).unwrap();
    assert_eq!((directory.uid(), directory.mode() & 0o777), (0, 0o700));
    let request = server.finish().to_ascii_lowercase();
    for header in [
        "if-match: \"version-a\"\r\n",
        "range: bytes=100-109\r\n",
        "accept-encoding: identity\r\n",
    ] {
        assert!(request.contains(header), "{request}");
    }
}

#[test]
fn tls_range_rejects_200_412_and_redirect_without_following() {
    for status in [200, 412, 302] {
        let mut headers = good_headers();
        headers.push(("Location", "https://127.0.0.1:1/forbidden"));
        assert!(rejected_range(response(status, &headers, b"0123456789")).contains("requires206"));
    }
}

#[test]
fn tls_range_rejects_changed_missing_and_duplicate_etags() {
    for etag in [None, Some("\"other\""), Some("W/\"version-a\"")] {
        let mut headers = good_headers();
        headers.retain(|(key, _)| *key != "ETag");
        if let Some(value) = etag {
            headers.push(("ETag", value));
        }
        rejected_range(response(206, &headers, b"0123456789"));
    }
    let mut headers = good_headers();
    headers.push(("ETag", "\"version-a\""));
    assert!(rejected_range(response(206, &headers, b"0123456789")).contains("duplicated"));
}

#[test]
fn tls_range_rejects_encoded_transfer_and_wrong_boundaries() {
    for (key, value) in [
        ("Content-Encoding", "gzip"),
        ("Transfer-Encoding", "chunked"),
        ("Content-Range", "bytes 101-110/1000"),
        ("Content-Range", "bytes 100-109/1001"),
        ("Content-Length", "11"),
        ("x-goog-generation", "unexpected"),
    ] {
        let mut headers = good_headers();
        headers.retain(|(name, _)| *name != key);
        headers.push((key, value));
        rejected_range(response(206, &headers, b"0123456789"));
    }
}

#[test]
fn tls_truncated_body_keeps_partial_bytes_without_promoting_them() {
    let server = Server::start(response(206, &good_headers(), b"short"), Duration::ZERO);
    let mut out = output();
    assert!(
        runtime()
            .block_on(get(
                &client(),
                &mut out,
                "range",
                &server.url,
                &representation_fixture(),
                (100, 10),
                deadline(Duration::from_secs(5)),
            ))
            .is_err()
    );
    server.finish();
    assert_eq!(fs::read(out.path.join("range.bin")).unwrap(), b"short");
    assert!(!out.members.contains_key("range.bin"));
    assert!(!out.path.join("completion.json").exists());
}

#[test]
fn tls_request_cannot_outlive_the_original_capture_deadline() {
    let server = Server::start(
        response(206, &good_headers(), b"short"),
        Duration::from_millis(700),
    );
    let mut out = output();
    let start = Instant::now();
    assert!(
        runtime()
            .block_on(get(
                &client(),
                &mut out,
                "range",
                &server.url,
                &representation_fixture(),
                (100, 10),
                deadline(Duration::from_millis(250)),
            ))
            .is_err()
    );
    assert!(start.elapsed() < Duration::from_secs(2));
    server.finish();
    assert!(!out.members.contains_key("range.bin"));
}

#[test]
fn production_https_policy_rejects_plain_http() {
    let mut out = output();
    assert!(
        runtime()
            .block_on(head(
                &client(),
                &mut out,
                "head",
                "http://127.0.0.1:1/object",
                deadline(Duration::from_secs(2)),
            ))
            .is_err()
    );
}

#[test]
fn production_tls_policy_rejects_an_untrusted_certificate() {
    let server = Server::start(response(200, &good_headers(), b""), Duration::ZERO);
    let mut out = output();
    let strict = client_builder().build().unwrap();
    assert!(
        runtime()
            .block_on(head(
                &strict,
                &mut out,
                "head",
                &server.url,
                deadline(Duration::from_secs(5)),
            ))
            .is_err()
    );
    assert!(server.finish().starts_with("TLS/request rejected:"));
}
