//! Closed bounded GET/HEAD transport diagnostic. No custody or publication authority.
use super::*;
use std::net::{SocketAddr, ToSocketAddrs};

const COMMAND: &str = "probe-transport-holding213";
const ENDPOINT: &str = "https://995827f79dbd061b8d4fd07b4ca04414.r2.cloudflarestorage.com";
const HOST: &str = "995827f79dbd061b8d4fd07b4ca04414.r2.cloudflarestorage.com";
const BUCKET: &str = "solana-archive-with-accounts-data";
const KEY: &str = "foundation_node_01/objects/e9b0fa7bbad1fdbf86d9d564baa0c377003ec20e40709dae249fac8ba0cb91d9.blob";
const SOURCE: &str = "/home/ubuntu/.jetstreamer-private/qualification-213/diagnostic-output-selected-store8-v2/epoch-213-through-92447542.jet";
const OBJECT_SHA: &str = "e9b0fa7bbad1fdbf86d9d564baa0c377003ec20e40709dae249fac8ba0cb91d9";
const OBJECT_LENGTH: u64 = 125_316_500_795;
const OBJECT_ETAG: &str = "6933eb7a4efb4629b25550f0c1c433a1-1868";
const OFFSET: u64 = 8 << 30;
const WINDOW: usize = 32 << 20;
const REQUEST_SECONDS: u64 = 20;
const OUTPUT_PREFIX: &str = "horizon-holding213-transport-probe-";

fn arguments(args: &[String]) -> Result<(&Path, &str)> {
    ensure!(
        args.len() == 6
            && args[1] == COMMAND
            && args[2] == "--output"
            && args[4] == "--self-sha256",
        "closed holding 213 probe arguments differ"
    );
    ensure!(
        args[5].len() == 64
            && args[5]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid sealed probe digest"
    );
    Ok((Path::new(&args[3]), &args[5]))
}
fn range() -> String {
    format!("bytes={OFFSET}-{}", OFFSET + WINDOW as u64 - 1)
}
fn content_range() -> String {
    format!(
        "bytes {OFFSET}-{}/{OBJECT_LENGTH}",
        OFFSET + WINDOW as u64 - 1
    )
}
fn bounds(length: Option<u64>, content: Option<&str>, etag: Option<&str>) -> Result<()> {
    ensure!(
        length == Some(WINDOW as u64)
            && content == Some(content_range().as_str())
            && etag.map(normalize_etag) == Some(OBJECT_ETAG),
        "bounded response identity differs"
    );
    Ok(())
}
fn append(bytes: &mut Vec<u8>, chunk: &[u8]) -> Result<()> {
    ensure!(
        chunk.len() <= WINDOW.saturating_sub(bytes.len()),
        "bounded response body exceeds window"
    );
    bytes.extend_from_slice(chunk);
    Ok(())
}
fn matched(bytes: &[u8], expected: &[u8]) -> Result<Value> {
    ensure!(
        bytes.len() == WINDOW && expected.len() == WINDOW && bytes == expected,
        "bounded response bytes differ from retained source"
    );
    Ok(
        serde_json::json!({"success":true,"bytes":bytes.len(),"sha256":format!("{:x}",Sha256::digest(bytes))}),
    )
}
fn address(addresses: &[SocketAddr], ipv6: bool) -> Option<SocketAddr> {
    addresses.iter().copied().find(|a| a.is_ipv6() == ipv6)
}
fn authority() -> Value {
    serde_json::json!({"whole_object_verified":false,"custody_authorized":false,
        "publication_authorized":false,"retirement_authorized":false,"archive_mutations":false,
        "sidecar_mutations":false,"r2_mutations":false,"service_mutations":false})
}
fn result(attempt: Result<Value>, elapsed: u128) -> Value {
    // Errors crossing this boundary contain only our fixed diagnostics.
    serde_json::json!({"elapsed_millis":elapsed,"result":match attempt {
        Ok(v)=>v, Err(e)=>serde_json::json!({"success":false,"error":e.to_string()}) }})
}
async fn timed<F>(future: F) -> Result<Value>
where
    F: std::future::Future<Output = Result<Value>>,
{
    tokio::time::timeout(Duration::from_secs(REQUEST_SECONDS), future)
        .await
        .map_err(|_| anyhow!("bounded transport request reached 20-second timeout"))?
}
async fn sdk_window(client: &Client, expected: &[u8]) -> Result<Value> {
    let mut response = client
        .get_object()
        .bucket(BUCKET)
        .key(KEY)
        .range(range())
        .if_match(format!("\"{OBJECT_ETAG}\""))
        .send()
        .await
        .map_err(|_| anyhow!("SDK bounded GET failed"))?;
    bounds(
        response
            .content_length()
            .and_then(|n| u64::try_from(n).ok()),
        response.content_range(),
        response.e_tag(),
    )?;
    let mut bytes = Vec::with_capacity(WINDOW);
    while let Some(chunk) = response
        .body
        .try_next()
        .await
        .map_err(|_| anyhow!("SDK bounded body failed"))?
    {
        append(&mut bytes, &chunk)?;
    }
    matched(&bytes, expected)
}
async fn direct_window(client: &Client, peer: SocketAddr, expected: &[u8]) -> Result<Value> {
    // This signed request exists only in memory and can authorize GET of this
    // exact key, range and If-Match. Never format its URI, headers or errors.
    let signed = client
        .get_object()
        .bucket(BUCKET)
        .key(KEY)
        .range(range())
        .if_match(format!("\"{OBJECT_ETAG}\""))
        .presigned(aws_sdk_s3::presigning::PresigningConfig::expires_in(
            Duration::from_secs(120),
        )?)
        .await
        .map_err(|_| anyhow!("bounded GET signing failed"))?;
    let http = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .resolve(HOST, peer)
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(REQUEST_SECONDS))
        .build()
        .map_err(|_| anyhow!("bounded HTTPS client setup failed"))?;
    let mut request = http.get(signed.uri());
    for (key, value) in signed.headers() {
        request = request.header(key, value);
    }
    let mut response = request
        .send()
        .await
        .map_err(|_| anyhow!("direct bounded GET failed"))?;
    ensure!(
        response.status() == reqwest::StatusCode::PARTIAL_CONTENT,
        "direct GET did not return 206"
    );
    bounds(
        response.content_length(),
        response
            .headers()
            .get(CONTENT_RANGE)
            .and_then(|h| h.to_str().ok()),
        response.headers().get(ETAG).and_then(|h| h.to_str().ok()),
    )?;
    let mut bytes = Vec::with_capacity(WINDOW);
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| anyhow!("direct bounded body failed"))?
    {
        append(&mut bytes, &chunk)?;
    }
    matched(&bytes, expected)
}
pub(super) async fn run() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    let (output, self_sha) = arguments(&args)?;
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "probe requires root private receipt identity"
    );
    let executable = fs::read_link("/proc/self/exe")?;
    let em = fs::symlink_metadata(&executable)?;
    ensure!(
        em.is_file()
            && em.uid() == 0
            && em.nlink() == 1
            && em.mode() & 0o222 == 0
            && em.len() < 256 << 20,
        "probe executable is not sealed"
    );
    ensure!(
        format!("{:x}", Sha256::digest(fs::read(&executable)?)) == self_sha,
        "probe executable differs"
    );
    let parent = output.parent().context("missing private output parent")?;
    let pm = fs::symlink_metadata(parent)?;
    ensure!(
        output.is_absolute()
            && parent.canonicalize()? == parent
            && parent.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && parent
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with(OUTPUT_PREFIX))
            && output.file_name().is_some_and(|s| s == "probe.json")
            && pm.is_dir()
            && pm.uid() == 0
            && pm.mode() & 0o777 == 0o700,
        "foreign private probe output"
    );
    ensure!(!output.try_exists()?, "probe output occupied");
    let source = Path::new(SOURCE);
    ensure!(
        source.canonicalize()? == source,
        "retained source path changed"
    );
    let before = regular_identity(source)?;
    ensure!(
        before.length == OBJECT_LENGTH,
        "retained source length differs"
    );
    let mut local = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(source)?;
    ensure!(
        identity(&local.metadata()?) == before,
        "retained source open identity differs"
    );
    local.seek(SeekFrom::Start(OFFSET))?;
    let mut expected = vec![0; WINDOW];
    local.read_exact(&mut expected)?;
    let config =
        r2_config_from_env().map_err(|_| anyhow!("closed probe R2 environment differs"))?;
    ensure!(
        config.endpoint == ENDPOINT && config.bucket == BUCKET,
        "closed probe endpoint or bucket differs"
    );
    let client = s3_client(&config);
    let head = tokio::time::timeout(
        Duration::from_secs(REQUEST_SECONDS),
        client.head_object().bucket(BUCKET).key(KEY).send(),
    )
    .await
    .map_err(|_| anyhow!("bounded HEAD reached timeout"))?
    .map_err(|_| anyhow!("bounded HEAD failed"))?;
    ensure!(
        head.content_length().and_then(|n| u64::try_from(n).ok()) == Some(OBJECT_LENGTH)
            && head.e_tag().map(normalize_etag) == Some(OBJECT_ETAG),
        "exact holding object identity differs"
    );
    let started = Instant::now();
    let sdk = result(
        timed(sdk_window(&client, &expected)).await,
        started.elapsed().as_millis(),
    );
    // DNS is separate from transport timings and cannot block the runtime thread.
    let dns = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::task::spawn_blocking(|| {
            (HOST, 443)
                .to_socket_addrs()
                .map(|a| a.take(16).collect::<Vec<_>>())
        }),
    )
    .await;
    let addresses = match dns {
        Ok(Ok(Ok(a))) => a,
        _ => Vec::new(),
    };
    let mut comparisons = Vec::new();
    for ipv6 in [false, true] {
        let started = Instant::now();
        let mut row = if let Some(peer) = address(&addresses, ipv6) {
            let mut row = result(
                timed(direct_window(&client, peer, &expected)).await,
                started.elapsed().as_millis(),
            );
            row["peer"] = serde_json::json!(peer.ip().to_string());
            row
        } else {
            result(
                Err(anyhow!(
                    "requested address family unavailable or DNS timed out"
                )),
                0,
            )
        };
        row["ipv6"] = serde_json::json!(ipv6);
        comparisons.push(row);
    }
    ensure!(
        regular_identity(source)? == before && identity(&local.metadata()?) == before,
        "retained source changed during bounded comparison"
    );
    let report = serde_json::json!({"schema":"jetstreamer-private-holding213-transport-probe-v1",
        "object_key":KEY,"object_length":OBJECT_LENGTH,"object_etag":OBJECT_ETAG,
        "expected_whole_object_sha256":OBJECT_SHA,"range_start":OFFSET,"range_bytes":WINDOW,
        "maximum_response_body_bytes":3*WINDOW,"sdk":sdk,"results":comparisons,"authority":authority()});
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer_pretty(temporary.as_file_mut(), &report)?;
    temporary.write_all(b"\n")?;
    persist_noclobber(temporary, output)?;
    File::open(parent)?.sync_all()?;
    println!("{}", output.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn profile_accepts_only_output_and_sealed_digest() {
        let args = vec![
            "helper".into(),
            COMMAND.into(),
            "--output".into(),
            "/private/probe.json".into(),
            "--self-sha256".into(),
            "a".repeat(64),
        ];
        assert!(arguments(&args).is_ok());
        for (index, foreign) in [
            (1, "probe-transport-203"),
            (2, "--key"),
            (4, "--source"),
            (5, "not-a-digest"),
        ] {
            let mut changed = args.clone();
            changed[index] = foreign.into();
            assert!(arguments(&changed).is_err());
        }
        let mut extra = args;
        extra.push("--url".into());
        assert!(arguments(&extra).is_err());
    }
    #[test]
    fn exact_response_identity_and_fixed_window_are_required() {
        assert_eq!(range(), "bytes=8589934592-8623489023");
        let cr = content_range();
        assert!(bounds(Some(WINDOW as u64), Some(&cr), Some(OBJECT_ETAG)).is_ok());
        for (length, content, etag) in [
            (Some(OBJECT_LENGTH), Some(cr.as_str()), Some(OBJECT_ETAG)),
            (Some(WINDOW as u64), Some("bytes 0-1/2"), Some(OBJECT_ETAG)),
            (Some(WINDOW as u64), Some(cr.as_str()), Some("new-version")),
            (None, Some(cr.as_str()), Some(OBJECT_ETAG)),
        ] {
            assert!(bounds(length, content, etag).is_err());
        }
    }
    #[test]
    fn bounded_body_cannot_overgrow_and_truncated_or_wrong_bytes_fail() {
        let expected = vec![1; WINDOW];
        assert!(matched(&expected, &expected).is_ok());
        assert!(matched(&expected[..WINDOW - 1], &expected).is_err());
        let mut wrong = expected.clone();
        wrong[0] = 2;
        assert!(matched(&wrong, &expected).is_err());
        assert!(append(&mut wrong, &[1]).is_err());
        assert_eq!(wrong.len(), WINDOW);
    }
    #[test]
    fn missing_address_family_is_optional_and_authority_is_always_denied() {
        let peers = ["127.0.0.1:443".parse().unwrap()];
        assert!(address(&peers, false).is_some());
        assert!(address(&peers, true).is_none());
        assert!(
            authority()
                .as_object()
                .unwrap()
                .values()
                .all(|v| v == &Value::Bool(false))
        );
    }
}
