use crate::{Result, ensure, hash, write_new};
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    ssl::{SslAcceptor, SslMethod},
    x509::{
        X509, X509NameBuilder,
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
    },
};
use serde::Serialize;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    os::fd::FromRawFd,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

const HOST: &str = "files.old-faithful.net";
const INDEX_BYTES: usize = 5_184_000;
const RECORD: usize = 152_191 * 12;
const SEGMENT_OFFSET: u64 = 32;
const SEGMENT_LENGTH: u32 = 8;

pub struct Certificates {
    trusted: Arc<SslAcceptor>,
    untrusted: Arc<SslAcceptor>,
    wrong_name: Arc<SslAcceptor>,
}

fn authority(serial: u32) -> Result<(X509, PKey<Private>)> {
    let key = PKey::from_rsa(Rsa::generate(2048)?)?;
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text(
        "CN",
        "Epoch 168 native fixture CA; not an origin certificate",
    )?;
    let name = name.build();
    let mut certificate = X509::builder()?;
    certificate.set_version(2)?;
    certificate.set_serial_number(BigNum::from_u32(serial)?.to_asn1_integer()?.as_ref())?;
    certificate.set_subject_name(&name)?;
    certificate.set_issuer_name(&name)?;
    certificate.set_pubkey(&key)?;
    certificate.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
    certificate.set_not_after(Asn1Time::days_from_now(1)?.as_ref())?;
    certificate.append_extension(BasicConstraints::new().critical().ca().build()?)?;
    certificate.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?,
    )?;
    certificate.sign(&key, MessageDigest::sha256())?;
    Ok((certificate.build(), key))
}

fn endpoint(
    ca: &X509,
    ca_key: &PKey<Private>,
    hostname: &str,
    serial: u32,
) -> Result<Arc<SslAcceptor>> {
    let key = PKey::from_rsa(Rsa::generate(2048)?)?;
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", hostname)?;
    let name = name.build();
    let mut certificate = X509::builder()?;
    certificate.set_version(2)?;
    certificate.set_serial_number(BigNum::from_u32(serial)?.to_asn1_integer()?.as_ref())?;
    certificate.set_subject_name(&name)?;
    certificate.set_issuer_name(ca.subject_name())?;
    certificate.set_pubkey(&key)?;
    certificate.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
    certificate.set_not_after(Asn1Time::days_from_now(1)?.as_ref())?;
    certificate.append_extension(BasicConstraints::new().critical().build()?)?;
    certificate.append_extension(
        KeyUsage::new()
            .critical()
            .digital_signature()
            .key_encipherment()
            .build()?,
    )?;
    certificate.append_extension(ExtendedKeyUsage::new().server_auth().build()?)?;
    let san = SubjectAlternativeName::new()
        .dns(hostname)
        .build(&certificate.x509v3_context(Some(ca), None))?;
    certificate.append_extension(san)?;
    certificate.sign(ca_key, MessageDigest::sha256())?;
    let certificate = certificate.build();
    let mut tls = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())?;
    tls.set_private_key(&key)?;
    tls.set_certificate(&certificate)?;
    tls.add_extra_chain_cert(ca.to_owned())?;
    tls.check_private_key()?;
    Ok(Arc::new(tls.build()))
}

impl Certificates {
    pub fn prepare(trust_directory: &Path) -> Result<Self> {
        let (trusted_ca, trusted_key) = authority(1)?;
        let (other_ca, other_key) = authority(2)?;
        write_new(
            &trust_directory.join("ca-certificates.crt"),
            &trusted_ca.to_pem()?,
        )?;
        Ok(Self {
            trusted: endpoint(&trusted_ca, &trusted_key, HOST, 10)?,
            untrusted: endpoint(&other_ca, &other_key, HOST, 11)?,
            wrong_name: endpoint(&trusted_ca, &trusted_key, "wrong-name.invalid", 12)?,
        })
    }
}

#[derive(Clone, Default, Serialize)]
pub struct Trace {
    pub connections: usize,
    pub tls_errors: Vec<String>,
    pub requests: Vec<Exchange>,
    pub proxy_connections: usize,
    pub fixture_errors: Vec<String>,
    pub fault_applied: bool,
}

#[derive(Clone, Serialize)]
pub struct Exchange {
    pub request_headers: String,
    pub response_headers: String,
    pub response_body_bytes: usize,
    pub response_body_bytes_written: usize,
    pub response_body_sha256: String,
    pub write_error: Option<String>,
}

fn listen(port: u16) -> Result<TcpListener> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    ensure(fd >= 0, "fixture socket")?;
    let listener = unsafe { TcpListener::from_raw_fd(fd) };
    let enabled: libc::c_int = 1;
    ensure(
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                (&enabled as *const libc::c_int).cast(),
                std::mem::size_of_val(&enabled) as _,
            )
        } == 0,
        "fixture SO_REUSEADDR",
    )?;
    let address = libc::sockaddr_in {
        sin_family: libc::AF_INET as _,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        },
        sin_zero: [0; 8],
    };
    ensure(
        unsafe {
            libc::bind(
                fd,
                (&address as *const libc::sockaddr_in).cast(),
                std::mem::size_of_val(&address) as _,
            )
        } == 0,
        "fixture bind",
    )?;
    ensure(unsafe { libc::listen(fd, 16) } == 0, "fixture listen")?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

struct Response {
    headers: String,
    body: Vec<u8>,
    delay_body: bool,
    fault_applied: bool,
}

fn response(request: &str, scenario: &str, request_number: usize) -> Result<Response> {
    let lines: Vec<_> = request.split("\r\n").collect();
    let first: Vec<_> = lines[0].split_whitespace().collect();
    ensure(
        first.len() == 3 && first[2] == "HTTP/1.1",
        "unexpected fixture HTTP request line",
    )?;
    let method = first[0];
    let index = match first[1] {
        "/168/epoch-168.car" => false,
        "/168/epoch-168-slot-ranges.raw" => true,
        _ => return Err("capture followed a redirect or requested a foreign path".into()),
    };
    ensure(method == "HEAD" || method == "GET", "fixture method")?;
    let expected_request = match request_number {
        1 | 7 => ("HEAD", false),
        2 | 8 => ("HEAD", true),
        3 => ("GET", true),
        4..=6 => ("GET", false),
        _ => return Err("unexpected extra fixture request".into()),
    };
    ensure(
        (method, index) == expected_request,
        "capture changed the fixed method/object sequence",
    )?;
    let mut object = if index {
        vec![0u8; INDEX_BYTES]
    } else {
        (0..128).map(|n| n as u8).collect::<Vec<_>>()
    };
    if index {
        object[RECORD..RECORD + 8].copy_from_slice(&SEGMENT_OFFSET.to_le_bytes());
        object[RECORD + 8..RECORD + 12].copy_from_slice(&SEGMENT_LENGTH.to_le_bytes());
        match scenario {
            "index-zero" => object[RECORD..RECORD + 12].fill(0),
            "index-outside" => object[RECORD..RECORD + 8].copy_from_slice(&1000u64.to_le_bytes()),
            "index-overflow" => object[RECORD..RECORD + 8].copy_from_slice(&u64::MAX.to_le_bytes()),
            "index-header-overlap" => {
                object[RECORD..RECORD + 8].copy_from_slice(&1u64.to_le_bytes())
            }
            "index-oversized" => {
                object[RECORD + 8..RECORD + 12].copy_from_slice(&(256u32 << 20).to_le_bytes())
            }
            _ => (),
        }
    } else {
        // Deliberately synthetic: the transport does not claim CAR semantics.
        object[0] = 1;
        object[1] = 0xa0;
        match scenario {
            "header-nonminimal" => {
                object[0] = 0x81;
                object[1] = 0;
            }
            "header-oversized" => {
                object[0] = 0x81;
                object[1] = 8;
            }
            "header-varint-overflow" => object[..10].fill(0x80),
            "header-zero" => object[0] = 0,
            _ => (),
        }
    }
    // The oversized target-range control advertises a large virtual CAR but
    // serves only its tiny header. This isolates MAX_INPUT from the separate
    // outside-object rejection without allocating a large fixture body.
    let object_length = if !index && scenario == "index-oversized" {
        512usize << 20
    } else {
        object.len()
    };
    let etag = if index {
        "\"fixture-index-v1\""
    } else {
        "\"fixture-car-v1\""
    };
    let lookup = |name: &str| -> Result<String> {
        let values: Vec<_> = lines
            .iter()
            .filter_map(|line| line.split_once(':'))
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.trim())
            .collect();
        ensure(
            values.len() == 1,
            "missing/duplicated fixture request header",
        )?;
        Ok(values[0].to_owned())
    };
    ensure(
        lookup("host")? == HOST,
        "capture changed the fixed origin Host header",
    )?;
    ensure(
        lookup("accept-encoding")? == "identity",
        "capture requested decoded representation",
    )?;
    let (mut body, mut content_length, mut status, mut content_range) = if method == "HEAD" {
        (Vec::new(), object_length, "200 OK", None)
    } else {
        ensure(
            lookup("if-match")? == etag,
            "capture omitted or changed conditional identity",
        )?;
        let range = lookup("range")?;
        let (begin, end) = range
            .strip_prefix("bytes=")
            .ok_or("fixture Range prefix")?
            .split_once('-')
            .ok_or("fixture Range split")?;
        let begin: usize = begin.parse()?;
        let end: usize = end.parse()?;
        ensure(
            begin <= end && end < object.len(),
            "capture requested outside fixture object",
        )?;
        let expected = match request_number {
            3 => (0, INDEX_BYTES - 1),
            4 => (0, 9),
            5 => (0, 1),
            6 => (
                SEGMENT_OFFSET as usize,
                (SEGMENT_OFFSET + u64::from(SEGMENT_LENGTH) - 1) as usize,
            ),
            _ => return Err("unexpected fixture GET sequence".into()),
        };
        ensure(
            (begin, end) == expected,
            "capture changed the fixed request sequence",
        )?;
        (
            object[begin..=end].to_vec(),
            end - begin + 1,
            "206 Partial Content",
            Some(format!("bytes {begin}-{end}/{object_length}")),
        )
    };
    let mut extra = Vec::<String>::new();
    let mut response_etag = Some(etag.to_owned());
    let mut version = Some("fixture-version-1".to_owned());
    let mut fault_applied = false;
    let mut omit_length = false;
    let mut delay_body = false;
    if request_number == 1 {
        match scenario {
            "head-weak-etag" => {
                response_etag = Some(format!("W/{etag}"));
                fault_applied = true;
            }
            "head-missing-etag" => {
                response_etag = None;
                fault_applied = true;
            }
            "head-duplicate-etag" => {
                extra.push(format!("ETag: {etag}"));
                fault_applied = true;
            }
            "head-missing-length" => {
                omit_length = true;
                fault_applied = true;
            }
            "head-zero-length" => {
                content_length = 0;
                fault_applied = true;
            }
            "head-redirect" => {
                status = "302 Found";
                extra.push(format!("Location: https://{HOST}/redirect-target"));
                fault_applied = true;
            }
            _ => (),
        }
    }
    if request_number == 3 {
        match scenario {
            "range-http200" => {
                status = "200 OK";
                fault_applied = true;
            }
            "range-http412" => {
                status = "412 Precondition Failed";
                fault_applied = true;
            }
            "range-redirect" => {
                status = "302 Found";
                extra.push(format!("Location: https://{HOST}/redirect-target"));
                fault_applied = true;
            }
            "range-changed-etag" => {
                response_etag = Some("\"changed\"".into());
                fault_applied = true;
            }
            "range-duplicate-etag" => {
                extra.push(format!("ETag: {etag}"));
                fault_applied = true;
            }
            "range-wrong-offset" => {
                content_range = Some(format!("bytes 1-{INDEX_BYTES}/{INDEX_BYTES}"));
                fault_applied = true;
            }
            "range-wrong-total" => {
                content_range = Some(format!("bytes 0-{}/{}", INDEX_BYTES - 1, INDEX_BYTES + 1));
                fault_applied = true;
            }
            "range-wrong-length" => {
                content_length += 1;
                fault_applied = true;
            }
            "range-gzip" => {
                extra.push("Content-Encoding: gzip".into());
                fault_applied = true;
            }
            "range-chunked-overflow" => {
                omit_length = true;
                extra.push("Transfer-Encoding: chunked".into());
                body = b"100000000\r\nnot-a-complete-chunk\r\n".to_vec();
                fault_applied = true;
            }
            "range-truncated" => {
                body.truncate(17);
                fault_applied = true;
            }
            "range-version-disappears" => {
                version = None;
                fault_applied = true;
            }
            "range-version-changes" => {
                version = Some("different-version".into());
                fault_applied = true;
            }
            "range-version-appears" => {
                extra.push("x-goog-generation: new-version".into());
                fault_applied = true;
            }
            "range-version-duplicates" => {
                extra.push("x-amz-version-id: fixture-version-1".into());
                fault_applied = true;
            }
            name if name.starts_with("index-") => fault_applied = true,
            _ => (),
        }
    }
    if request_number == 4 && scenario.starts_with("header-") {
        fault_applied = true;
        if scenario == "header-truncated" {
            body.truncate(1);
        }
    }
    if request_number == 5 && scenario == "header-changes" {
        body[1] ^= 1;
        fault_applied = true;
    }
    if request_number == 6 && scenario == "socket-timeout" {
        delay_body = true;
        fault_applied = true;
    }
    if request_number == 7 && scenario == "posthead-changed" {
        response_etag = Some("\"changed-after\"".into());
        fault_applied = true;
    }
    if request_number == 8 && scenario == "posthead-version-disappears" {
        version = None;
        fault_applied = true;
    }
    let mut headers = format!("HTTP/1.1 {status}\r\nConnection: close\r\n");
    if !omit_length {
        headers.push_str(&format!("Content-Length: {content_length}\r\n"));
    }
    if let Some(etag) = response_etag {
        headers.push_str(&format!("ETag: {etag}\r\n"));
    }
    if let Some(value) = version {
        headers.push_str(&format!("x-amz-version-id: {value}\r\n"));
    }
    if let Some(value) = content_range {
        headers.push_str(&format!("Content-Range: {value}\r\n"));
    }
    for value in extra {
        headers.push_str(&value);
        headers.push_str("\r\n");
    }
    headers.push_str("\r\n");
    Ok(Response {
        headers,
        body,
        delay_body,
        fault_applied,
    })
}

fn read_request(stream: &mut impl Read) -> Result<String> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        ensure(bytes.len() < 8192, "fixture request header limit")?;
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte)?;
        bytes.push(byte[0]);
    }
    Ok(String::from_utf8(bytes)?)
}

fn serve(
    stream: TcpStream,
    tls: &SslAcceptor,
    scenario: &str,
    trace: &Mutex<Trace>,
    stop: &AtomicBool,
) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    trace.lock().map_err(|_| "trace poisoned")?.connections += 1;
    let mut stream = match tls.accept(stream) {
        Ok(stream) => stream,
        Err(error) => {
            trace
                .lock()
                .map_err(|_| "trace poisoned")?
                .tls_errors
                .push(error.to_string());
            return Ok(());
        }
    };
    let request = read_request(&mut stream)?;
    let number = trace.lock().map_err(|_| "trace poisoned")?.requests.len() + 1;
    let reply = response(&request, scenario, number)?;
    let mut write_error = stream
        .write_all(reply.headers.as_bytes())
        .err()
        .map(|e| e.to_string());
    let headers_written = write_error.is_none();
    if reply.delay_body {
        // The real capture's 30-second read timeout must fire. The supervisor
        // gives it 45 seconds and never calls this timeout a successful case.
        for _ in 0..320 {
            if stop.load(Ordering::SeqCst) {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
    let mut body_written = 0;
    while write_error.is_none() && body_written < reply.body.len() {
        match stream.write(&reply.body[body_written..]) {
            Ok(0) => write_error = Some("fixture body write returned zero".into()),
            Ok(written) => body_written += written,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => (),
            Err(error) => write_error = Some(error.to_string()),
        }
    }
    let mut trace = trace.lock().map_err(|_| "trace poisoned")?;
    trace.fault_applied |= reply.fault_applied && headers_written;
    trace.requests.push(Exchange {
        request_headers: request,
        response_headers: reply.headers,
        response_body_bytes: reply.body.len(),
        response_body_bytes_written: body_written,
        response_body_sha256: hash(&reply.body),
        write_error,
    });
    Ok(())
}

pub struct Server {
    stop: Arc<AtomicBool>,
    trace: Arc<Mutex<Trace>>,
    thread: Option<JoinHandle<()>>,
}

impl Server {
    pub fn start(certificates: &Certificates, scenario: &str) -> Result<Self> {
        let tls = match scenario {
            "tls-untrusted" => Arc::clone(&certificates.untrusted),
            "tls-wrong-name" => Arc::clone(&certificates.wrong_name),
            _ => Arc::clone(&certificates.trusted),
        };
        let listener = listen(443)?;
        let proxy = listen(444)?;
        let stop = Arc::new(AtomicBool::new(false));
        let trace = Arc::new(Mutex::new(Trace::default()));
        let thread_stop = Arc::clone(&stop);
        let thread_trace = Arc::clone(&trace);
        let scenario = scenario.to_owned();
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        if let Err(error) =
                            serve(stream, &tls, &scenario, &thread_trace, &thread_stop)
                            && let Ok(mut trace) = thread_trace.lock()
                        {
                            trace.fixture_errors.push(error.to_string());
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => (),
                    Err(error) => {
                        if let Ok(mut trace) = thread_trace.lock() {
                            trace.fixture_errors.push(error.to_string());
                        }
                        break;
                    }
                }
                if let Ok((stream, _)) = proxy.accept() {
                    drop(stream);
                    if let Ok(mut trace) = thread_trace.lock() {
                        trace.proxy_connections += 1;
                    }
                }
                thread::sleep(Duration::from_millis(5));
            }
        });
        Ok(Self {
            stop,
            trace,
            thread: Some(thread),
        })
    }

    pub fn finish(mut self) -> Result<Trace> {
        self.stop.store(true, Ordering::SeqCst);
        self.thread
            .take()
            .ok_or("fixture thread absent")?
            .join()
            .map_err(|_| "fixture thread panicked")?;
        Ok(self.trace.lock().map_err(|_| "trace poisoned")?.clone())
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
